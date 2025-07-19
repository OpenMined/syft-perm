"""Path matching and glob pattern utilities extracted from syft_perm implementation."""

from pathlib import PurePath


def _acl_norm_path(path: str) -> str:
    """
    Normalize a file system path for use in ACL operations by:
    1. Converting all path separators to forward slashes
    2. Cleaning the path (resolving . and ..)
    3. Removing leading path separators
    This ensures consistent path handling across different operating systems
    and compatibility with glob pattern matching.
    """
    # Convert to forward slashes using pathlib for proper path handling
    normalized = str(PurePath(path).as_posix())

    # Remove leading slashes and resolve . components
    normalized = normalized.lstrip("/")

    # Handle relative path components
    if normalized.startswith("./"):
        normalized = normalized[2:]
    elif normalized == ".":
        normalized = ""

    return normalized


def _doublestar_match(pattern: str, path: str) -> bool:
    """
    Match a path against a glob pattern using doublestar algorithm.
    This implementation matches the Go doublestar library behavior used in old syftbox.

    Args:
        pattern: Glob pattern (supports *, ?, ** for recursive)
        path: Path to match against pattern (should be normalized)

    Returns:
        bool: True if path matches pattern
    """
    # Normalize inputs
    pattern = _acl_norm_path(pattern)
    path = _acl_norm_path(path)

    # Quick exact match
    if pattern == path:
        return True

    # Handle ** patterns
    if "**" in pattern:
        return _match_doublestar(pattern, path)

    # Handle single * and ? patterns
    return _match_simple_glob(pattern, path)


def _match_doublestar(pattern: str, path: str) -> bool:
    """
    Handle patterns containing ** (doublestar) recursion.

    This implements the doublestar algorithm similar to the Go library used in
    old syftbox.
    Key behavior: ** matches zero or more path segments (directories).
    """
    # Handle the simplest cases first
    if pattern == "**":
        return True
    if not pattern:
        return not path
    if not path:
        return pattern == "**" or pattern == ""

    # Find the first ** in the pattern
    double_star_idx = pattern.find("**")
    if double_star_idx == -1:
        # No ** in pattern, use simple glob matching
        return _match_simple_glob(pattern, path)

    # Split into prefix (before **), and suffix (after **)
    prefix = pattern[:double_star_idx].rstrip("/")
    suffix = pattern[double_star_idx + 2 :].lstrip("/")

    # Match the prefix
    if prefix:
        # For doublestar patterns, prefix should match at the beginning of the
        # path or we need to try matching the entire pattern at later positions
        # (for leading **)
        if path == prefix:
            # Exact match
            remaining = ""
        elif path.startswith(prefix + "/"):
            # Path starts with prefix followed by separator
            remaining = path[len(prefix) + 1 :]
        elif _match_simple_glob(prefix, path):
            # Glob pattern matches entire path
            remaining = ""
        else:
            # Prefix doesn't match at start, for leading ** try at later positions
            if pattern.startswith("**/"):
                path_segments = path.split("/")
                for i in range(1, len(path_segments) + 1):
                    remaining_path = "/".join(path_segments[i:])
                    if _match_doublestar(pattern, remaining_path):
                        return True
            return False
    else:
        # No prefix, ** can match from the beginning
        remaining = path

    # Match the suffix
    if not suffix:
        # Pattern ends with **
        # Check if this came from a trailing /** (which requires something after)
        if pattern.endswith("/**"):
            # /** requires something after the prefix
            return bool(remaining)
        else:
            # ** at end matches everything remaining
            return True

    # Try matching suffix at every possible position in remaining path
    if not remaining:
        # No remaining path, but we have a suffix to match
        return suffix == ""

    # Split remaining path into segments and try matching suffix at each position
    remaining_segments = remaining.split("/")

    # Try exact match first
    if _match_doublestar(suffix, remaining):
        return True

    # Try matching suffix starting from each segment position
    for i in range(len(remaining_segments)):
        candidate = "/".join(remaining_segments[i:])
        if _match_doublestar(suffix, candidate):
            return True

    return False


def _match_suffix_recursive(suffix: str, path: str) -> bool:
    """Match suffix pattern against path, trying all possible positions."""
    if not suffix:
        return True

    if not path:
        return suffix == ""

    # Try matching suffix at current position
    if _match_simple_glob(suffix, path):
        return True

    # Try matching suffix at each segment
    path_segments = path.split("/")
    for i in range(len(path_segments)):
        test_path = "/".join(path_segments[i:])
        if _match_simple_glob(suffix, test_path):
            return True

    return False


def _match_simple_glob(pattern: str, path: str) -> bool:
    """Match simple glob patterns with *, ?, [] but no **. Case-sensitive matching."""
    if not pattern and not path:
        return True
    if not pattern:
        return False
    if not path:
        return pattern == "*" or all(c == "*" for c in pattern)

    # Handle exact match (case-sensitive)
    if pattern == path:
        return True

    # Convert glob pattern to regex-like matching (case-sensitive)
    pattern_idx = 0
    path_idx = 0
    star_pattern_idx = -1
    star_path_idx = -1

    while path_idx < len(path):
        if pattern_idx < len(pattern):
            if pattern[pattern_idx] == "*":
                # Found *, remember positions
                star_pattern_idx = pattern_idx
                star_path_idx = path_idx
                pattern_idx += 1
                continue
            elif pattern[pattern_idx] == "?":
                # ? matches any single char (case-sensitive)
                pattern_idx += 1
                path_idx += 1
                continue
            elif pattern[pattern_idx] == "[":
                # Character class matching like [0-9], [abc], etc.
                if _match_char_class(pattern, pattern_idx, path[path_idx]):
                    # Find end of character class
                    bracket_end = pattern.find("]", pattern_idx + 1)
                    if bracket_end != -1:
                        pattern_idx = bracket_end + 1
                        path_idx += 1
                        continue
                # If no matching bracket or no match, fall through to backtrack
            elif pattern[pattern_idx] == path[path_idx]:
                # Exact char match (case-sensitive)
                pattern_idx += 1
                path_idx += 1
                continue

        # No match at current position, backtrack if we have a *
        if star_pattern_idx >= 0:
            # For single *, don't match across directory boundaries
            if path[star_path_idx] == "/":
                return False
            pattern_idx = star_pattern_idx + 1
            star_path_idx += 1
            path_idx = star_path_idx
        else:
            return False

    # Skip trailing * in pattern
    while pattern_idx < len(pattern) and pattern[pattern_idx] == "*":
        pattern_idx += 1

    return pattern_idx == len(pattern)


def _match_char_class(pattern: str, start_idx: int, char: str) -> bool:
    """Match a character against a character class like [0-9], [abc], [!xyz]."""
    if start_idx >= len(pattern) or pattern[start_idx] != "[":
        return False

    # Find the end of the character class
    end_idx = pattern.find("]", start_idx + 1)
    if end_idx == -1:
        return False

    char_class = pattern[start_idx + 1 : end_idx]
    if not char_class:
        return False

    # Handle negation [!...] or [^...]
    negate = False
    if char_class[0] in "!^":
        negate = True
        char_class = char_class[1:]

    # Check for range patterns like 0-9, a-z
    i = 0
    matched = False
    while i < len(char_class):
        if i + 2 < len(char_class) and char_class[i + 1] == "-":
            # Range pattern like 0-9
            start_char = char_class[i]
            end_char = char_class[i + 2]
            if start_char <= char <= end_char:
                matched = True
                break
            i += 3
        else:
            # Single character
            if char_class[i] == char:
                matched = True
                break
            i += 1

    return matched if not negate else not matched


def _glob_match(pattern: str, path: str) -> bool:
    """
    Match a path against a glob pattern, supporting ** for recursive matching.
    This implementation uses doublestar algorithm to match old syftbox behavior.

    Args:
        pattern: Glob pattern (supports *, ?, ** for recursive)
        path: Path to match against pattern

    Returns:
        bool: True if path matches pattern
    """
    return _doublestar_match(pattern, path)


def _calculate_glob_specificity(pattern: str) -> int:
    """
    Calculate glob specificity score matching old syftbox algorithm.
    Higher scores = more specific patterns.

    Args:
        pattern: Glob pattern to score

    Returns:
        int: Specificity score (higher = more specific)
    """
    # Early return for the most specific glob patterns
    if pattern == "**":
        return -100
    elif pattern == "**/*":
        return -99

    # 2L + 10D - wildcard penalty
    # Use forward slash for glob patterns
    score = len(pattern) * 2 + pattern.count("/") * 10

    # Penalize base score for substr wildcards
    for i, c in enumerate(pattern):
        if c == "*":
            if i == 0:
                score -= 20  # Leading wildcards are very unspecific
            else:
                score -= 10  # Other wildcards are less penalized
        elif c in "?!][{":
            score -= 2  # Non * wildcards get smaller penalty

    return score


def _sort_rules_by_specificity(rules: list) -> list:
    """
    Sort rules by specificity (most specific first) matching old syftbox algorithm.

    Args:
        rules: List of rule dictionaries

    Returns:
        list: Rules sorted by specificity (descending)
    """
    # Create list of (rule, specificity) tuples
    rules_with_scores = []
    for rule in rules:
        pattern = rule.get("pattern", "")
        score = _calculate_glob_specificity(pattern)
        rules_with_scores.append((rule, score))

    # Sort by specificity (descending - higher scores first)
    rules_with_scores.sort(key=lambda x: x[1], reverse=True)

    # Return just the rules
    return [rule for rule, score in rules_with_scores]
