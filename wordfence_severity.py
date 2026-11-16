class WordfenceSeverityMapper:
    MAP = {
        "low": 2,
        "medium": 5,
        "high": 8,
        "critical": 9
    }

    @classmethod
    def score(cls, severity):
        return cls.MAP.get(severity.lower())


if __name__ == "__main__":
    for sev in ["low", "medium", "high", "critical"]:
        print(f"{sev}: {WordfenceSeverityMapper.score(sev)}")