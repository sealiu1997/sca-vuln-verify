"""SCA language enum helpers."""

from __future__ import annotations


LANGUAGE_ENUM_TO_ECOSYSTEM = {
    1: "maven",
    2: "c/cpp",
    4: "nuget",
    7: "php",
    8: "npm",
    9: "pypi",
    10: "go",
    11: "rubygems",
    12: "swift",
    13: "cargo",
    17: "rpm",
}

LANGUAGE_ENUM_TO_NAME = {
    1: "Java",
    2: "C/C++",
    4: "C#/.NET",
    7: "PHP",
    8: "JS/TS/Node.js",
    9: "Python",
    10: "Go",
    11: "Ruby",
    12: "Swift",
    13: "Rust",
    17: "RPM",
}


def language_enum_to_ecosystem(language_enum: int | str | None) -> str:
    try:
        enum_value = int(language_enum)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "unknown"
    return LANGUAGE_ENUM_TO_ECOSYSTEM.get(enum_value, "unknown")


def language_enum_to_name(language_enum: int | str | None) -> str:
    try:
        enum_value = int(language_enum)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "unknown"
    return LANGUAGE_ENUM_TO_NAME.get(enum_value, "unknown")
