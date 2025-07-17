__all__ = ["tabulate"]


def tabulate(rows, headers=None):
    if headers:
        lines = [" | ".join(headers)]
    else:
        lines = []
    for row in rows:
        lines.append(" | ".join(str(x) for x in row))
    return "\n".join(lines)
