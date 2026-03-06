def calculate_score(findings):
    total_score = 0
    breakdown = []

    for item in findings:
        footprint_type = item.get("type", "Unknown")
        severity = item.get("severity", "Low")

        if footprint_type == "SSH Login":
            score = 8
        elif footprint_type == "Sudo Usage":
            score = 7
        elif footprint_type == "Failed Login":
            score = 4
        elif footprint_type == "Bash History":
            score = 5
        elif footprint_type == "SSH Artifact":
            score = 9
        elif footprint_type == "Temp File":
            score = 3
        else:
            score = 2

        total_score += score

        breakdown.append({
            "type": footprint_type,
            "severity": severity,
            "score": score
        })

    risk_level = "Low"

    if total_score >= 20:
        risk_level = "High"
    elif total_score >= 10:
        risk_level = "Medium"

    return {
        "total_score": total_score,
        "risk_level": risk_level,
        "breakdown": breakdown
    }
