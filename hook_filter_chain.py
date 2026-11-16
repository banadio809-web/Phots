import re
from dataclasses import dataclass
from typing import List, Dict, Any

CT_DW = "data_write"
CT_DR = "data_read"
CT_V = "validation"
CT_S = "sanitization"
CT_O = "output"


@dataclass
class HR:
    hook: str
    func: str
    pri: int = 10
    filt: bool = False
    ln: int = 0


@dataclass
class Res:
    ct: str
    sev: int
    regs: List[HR] = None
    df: str = ""
    desc: str = ""

    def __post_init__(self):
        if self.regs is None:
            self.regs = []


class HFC:
    def __init__(self, code: str):
        self.sc = code
        self.regs = []
        self._p()

    def _p(self):
        pt = r"(add_action|add_filter)\s*\(\s*['\"]([^'\"]+)\s*['\"]\s*,\s*['\"]([^'\"]+)\s*['\"]"
        for m in re.finditer(pt, self.sc):
            c, mn, hf = m.group(1), m.group(2), m.group(3)
            is_f = c == "add_filter"
            pm = re.search(r"priority\s*=\s*(\d+)", m.group(0))
            pri = int(pm.group(1)) if pm else 10
            ln = self.sc[:m.start()].count("\n") + 1
            self.regs.append(HR(hf, mn, pri, is_f, ln))

    def _dp(self, n: str) -> Dict[str, bool]:
        nn = n.lower()
        return {
            "opt": "option" in nn,
            "get": "get_option" in nn or "update_option" in nn,
            "set": "update_option" in nn or "add_option" in nn,
            "out": nn.startswith("the_") or "echo" in nn or "print" in nn,
            "san": nn.startswith("sanitize_") or nn.startswith("esc_"),
            "val": nn.startswith("validate_") or nn.startswith("check_"),
        }

    def ac(self) -> Res:
        if not self.regs:
            return Res("data_read", 0, [], "No hooks/filters detected", "No hooks or filters found.")
        pt: Dict[str, bool] = {}
        for r in self.regs:
            pt.update(self._dp(r.func))
        ht = " ".join(r.hook for r in self.regs)
        pt.update(self._dp(ht))
        hs = pt.get("san", False)
        hv = pt.get("val", False)
        hw = pt.get("set", False)
        hr = pt.get("get", False)
        ho = pt.get("out", False)
        if hs and ho:
            ct = "sanitization"
            desc = "Sanitization chain: data filtered then output safely"
        elif hv:
            ct = "validation"
            desc = "Validation chain: input validated before use"
        elif hw and hr and not hs:
            ct = "data_write"
            desc = "Data write-then-read chain: option written then read without sanitization"
        elif hr and not hw:
            ct = "data_read"
            desc = "Data read chain: data read from hook/filter without write"
        elif hw:
            ct = "data_write"
            desc = "Data write chain: data written via hook/filter"
        elif ho:
            ct = "output"
            desc = "Output chain: data directed to output"
        else:
            ct = "data_read"
            desc = "Mixed data flow chain"
        bs = {"data_write": 65, "data_read": 40, "validation": 30, "sanitization": 10, "output": 25}
        se = bs.get(ct, 50)
        for r in self.regs:
            if r.filt and "option" in r.hook.lower():
                se += 15
            if r.pri > 20:
                se += 5
            fp = self._dp(r.func)
            if fp.get("out") and not fp.get("san"):
                se += 10
        se = min(max(se, 0), 100)
        df = {
            "data_write": "Option written then read without sanitization - XSS risk",
            "sanitization": "Input sanitized before output - low risk",
            "validation": "Input validated - medium risk",
            "data_read": "Data read from hook/filter without sanitization",
            "output": "Data directed to output",
        }.get(ct, "Mixed pattern")
        return Res(ct, se, self.regs, df, desc)


if __name__ == "__main__":
    php = '<?php\nadd_action(\'wp_head\',\'inject\');function inject(){$c=get_option(\'custom_script\');echo $c;}add_filter(\'the_content\',\'add_ads\');function add_ads($c){$a=get_option(\'ad_code\');return $c.$a;}add_filter(\'the_excerpt\',\'sanitize_excerpt\');function sanitize_excerpt($c):return esc_html($c);\n'
    a = HFC(php)
    r = a.ac()
    print("=" * 60)
    print("Hook/Filter Chain Analysis Result")
    print("=" * 60)
    print(f"Chain Type:   {r.ct}")
    print(f"Severity:     {r.severity}/100")
    print(f"Description:  {r.desc}")
    print(f"Data Flow:    {r.df}")
    print(f"Registrations: {len(r.regs)}")
    for x in r.regs:
        print(f"  - {x.hook} -> {x.func} (priority:{x.pri}, filter:{x.filt}, line:{x.ln})")
    print("=" * 60)