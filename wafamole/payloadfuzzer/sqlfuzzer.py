"""
Strategies and fuzzer class module. 

MySQL syntax only. MySQL supports comments with:
1) # with comment text while endline;
2) -- with comment text while endline;
2) /* <comment text> */ allwhere.

Examples:
mysql> SELECT 1+1;     # Этот комментарий продолжается до конца строки
mysql> SELECT 1+1;     -- Этот комментарий продолжается до конца строки
mysql> SELECT 1 /* Это комментарий в строке */ + 1;
mysql> SELECT 1+
/*
Это многострочный
комментарий
*/
1;

"""

import random
import re
import sqlparse
from wafamole.payloadfuzzer.fuzz_utils import (
    replace_random,
    filter_candidates,
    random_string,
    num_tautology,
    string_tautology,
    num_contradiction,
    string_contradiction,
    trailing_zeros
)


def reset_inline_comments(payload: str):
    """
    Removes a randomly chosen multi-line comment content.

    Arguments:
        payload: query payload (string)

    Returns:
        str: payload modified
    """
    positions = list(re.finditer(r"/\*[^(/\*|\*/)]*\*/", payload))

    if not positions:
        return payload

    pos = random.choice(positions).span()

    replacements = ["/**/"]

    replacement = random.choice(replacements)

    new_payload = payload[: pos[0]] + replacement + payload[pos[1] :]

    return new_payload


def logical_invariant(payload: str):
    """
    Adds an invariant boolean condition to the payload.

    E.g., expression OR False
    where expression is a numeric or string tautology such as 1=1 or 'x'<>'y'

    Arguments:
        payload: query payload (string)

    Returns:
        str: payload modified
    """
    # rule matching numeric tautologies
    num_tautologies_pos = list(re.finditer(r'\b(\d+)(\s*=\s*|\s+(?i:like)\s+)\1\b', payload))
    num_tautologies_neg = list(re.finditer(r'\b(\d+)(\s*(!=|<>)\s*|\s+(?i:not like)\s+)(?!\1\b)\d+\b', payload))
    # rule matching string tautologies
    string_tautologies_pos = list(re.finditer(r'(\'|\")([a-zA-Z]{1}[\w#@$]*)\1(\s*=\s*|\s+(?i:like)\s+)(\'|\")\2\4', payload))
    string_tautologies_neg = list(re.finditer(r'(\'|\")([a-zA-Z]{1}[\w#@$]*)\1(\s*(!=|<>)\s*|\s+(?i:not like)\s+)(\'|\")(?!\2)([a-zA-Z]{1}[\w#@$]*)\5', payload))
    results = num_tautologies_pos + num_tautologies_neg + string_tautologies_pos + string_tautologies_neg
    if not results:
        return payload
    candidate = random.choice(results)

    pos = candidate.end()

    replacement = random.choice(
        [
            # AND True
            " AND 1",
            " AND True",
            " AND " + num_tautology(),
            " AND " + string_tautology(),
            # OR False
            " OR 0",
            " OR False",
            " OR " + num_contradiction(),
            " OR " + string_contradiction(),
        ]
    )

    new_payload = payload[:pos] + replacement + payload[pos:]

    return new_payload


def change_tautologies(payload: str):
    """
    Replaces a randomly chosen numeric/string tautology with another one.

    Arguments:
        payload: query payload (string)

    Returns:
        str: payload modified
    """
    # rules matching numeric tautologies
    num_tautologies_pos = list(re.finditer(r'\b(\d+)(\s*=\s*|\s+(?i:like)\s+)\1\b', payload))
    num_tautologies_neg = list(re.finditer(r'\b(\d+)(\s*(!=|<>)\s*|\s+(?i:not like)\s+)(?!\1\b)\d+\b', payload))
    # rule matching string tautologies
    string_tautologies_pos = list(re.finditer(r'(\'|\")([a-zA-Z]{1}[\w#@$]*)\1(\s*=\s*|\s+(?i:like)\s+)(\'|\")\2\4', payload))
    string_tautologies_neg = list(re.finditer(r'(\'|\")([a-zA-Z]{1}[\w#@$]*)\1(\s*(!=|<>)\s*|\s+(?i:not like)\s+)(\'|\")(?!\2)([a-zA-Z]{1}[\w#@$]*)\5', payload))
    results = num_tautologies_pos + num_tautologies_neg + string_tautologies_pos + string_tautologies_neg
    if not results:
        return payload
    candidate = random.choice(results)

    while True:
        replacements = [num_tautology(), string_tautology()]
        replacement = random.choice(replacements)
        if candidate != replacement:
            break

    new_payload = (
        payload[: candidate.span()[0]] + replacement + payload[candidate.span()[1] :]
    )

    return new_payload


def spaces_to_comments(payload: str):
    """
    Replaces a randomly chosen space character with a multi-line comment (and vice-versa).

    Arguments:
        payload: query payload (string)

    Returns:
        str: payload modified
    """
    # TODO: make it selectable (can be mixed with other strategies)
    symbols = {" ": ["/**/"], "/**/": [" "]}

    symbols_in_payload = filter_candidates(symbols, payload)

    if not symbols_in_payload:
        return payload

    # Randomly choose symbol
    candidate_symbol = random.choice(symbols_in_payload)
    # Check for possible replacements
    replacements = symbols[candidate_symbol]
    # Choose one replacement randomly
    candidate_replacement = random.choice(replacements)

    # Apply mutation at one random occurrence in the payload
    return replace_random(payload, re.escape(candidate_symbol), candidate_replacement)


def spaces_to_whitespaces_alternatives(payload: str):
    """
    Replaces a randomly chosen whitespace character with another one.

    Arguments:
        payload: query payload (string)

    Returns:
        str: payload modified
    """
    # Renewed symbols to substitute space
    symbols = {
        # Space replacements
        " ": [
            "\t", "\n", "\f", "\v", "\xa0",
        ],
        # Tab replacements
        "\t": [
            " ", "\n", "\f", "\v", "\xa0",
        ],
        # Newline replacements
        "\n": [
            " ", "\t", "\f", "\v", "\xa0",
        ],
        # Form feed replacements
        "\f": [
            " ", "\t", "\n", "\v", "\xa0",
        ],
        # Vertical tab replacements
        "\v": [
            " ", "\t", "\n", "\f", "\xa0",
        ],
        # Non-breaking space replacements
        "\xa0": [
            " ", "\t", "\n", "\f", "\v",
        ]
    }

    symbols_in_payload = filter_candidates(symbols, payload)

    if not symbols_in_payload:
        return payload

    # Randomly choose symbol
    candidate_symbol = random.choice(symbols_in_payload)
    # Check for possible replacements
    replacements = symbols[candidate_symbol]
    # Choose one replacement randomly
    candidate_replacement = random.choice(replacements)

    # Apply mutation at one random occurrence in the payload
    return replace_random(payload, re.escape(candidate_symbol), candidate_replacement)


def random_case(payload: str):
    """
    Randomly changes the capitalization of the SQL keywords in the input payload.

    Arguments:
        payload: query payload (string)

    Returns:
        str: payload modified
    """
    tokens = []
    # Check if the payload is correctly parsed (safety check).
    try:
        parsed_payload = sqlparse.parse(payload)
    except Exception:
        # Just return the input payload if it cannot be parsed to avoid stopping the fuzzing
        return payload
    for t in parsed_payload:
        tokens.extend(list(t.flatten()))

    sql_keywords = set(sqlparse.keywords.KEYWORDS_COMMON.keys())
    # sql_keywords = ' '.join(list(sqlparse.keywords.KEYWORDS_COMMON..keys()) + list(sqlparse.keywords.KEYWORDS.keys()))

    # Make sure case swapping is applied only to SQL tokens
    new_payload = []
    for token in tokens:
        if token.value.upper() in sql_keywords:
            new_token = ''.join([c.swapcase() if random.random() > 0.5 else c for c in token.value])
            new_payload.append(new_token)
        else:
            new_payload.append(token.value)

    return "".join(new_payload)


def comment_rewriting(payload: str):
    """
    Changes the content of a randomly chosen in-line or multi-line comment.
    
    Arguments:
        payload: query payload (string)

    Returns:
        str: payload modified
    """
    p = random.random()

    if p < 0.5 and ("#" in payload or "-- " in payload):
        return payload + random_string(2)
    elif p >= 0.5 and re.search(r"/\*[^(/\*|\*/)]*\*/", payload):
        return replace_random(payload, r"/\*[^(/\*|\*/)]*\*/", "/*" + random_string() + "*/")
    else:
        return payload


def swap_int_repr(payload: str):
    """
    Changes the representation of a randomly chosen numerical constant with an equivalent one.

    Arguments:
        payload: query payload (string)

    Returns:
        str: payload modified
    """
    candidates = list(re.finditer(r'\b\d+\b', payload))

    if not candidates:
        return payload

    candidate_pos = random.choice(candidates).span()

    candidate = payload[candidate_pos[0] : candidate_pos[1]]

    replacements = [
        hex(int(candidate)),
        "(SELECT {})".format(candidate),
        # Removed by author
        # "({})".format(candidate),
        # "OCT({})".format(int(candidate)),
        # "HEX({})".format(int(candidate)),
        # "BIN({})".format(int(candidate))
    ]

    replacement = random.choice(replacements)

    return payload[: candidate_pos[0]] + replacement + payload[candidate_pos[1] :]


def swap_keywords(payload: str):
    """
    Replaces a randomly chosen SQL operator with a semantically equivalent one.

    Arguments:
        payload: query payload (string)

    Returns:
        str: payload modified
    """
    replacements = {
        # OR
        "||": [" OR ", " or "],
        "OR": ["||", "or"],
        "or": ["OR", "||"],
        # AND
        "&&": [" AND ", " and "],
        "AND": ["&&", "and"],
        "and": ["AND", "&&"],
        # Not equals
        "<>": ["!=", " NOT LIKE ", " not like "],
        "!=": ["<>", " NOT LIKE ", " not like "],
        "NOT LIKE": ["not like"],
        "not like": ["NOT LIKE"],
        # Equals
        "=": [" LIKE ", " like "],
        "LIKE": ["like"],
        "like": ["LIKE"]
    }

    # Use sqlparse to tokenize the payload in order to better match keywords,
    # even when they are composed by multiple keywords such as "NOT LIKE"
    tokens = []
    # Check if the payload is correctly parsed (safety check).
    try:
        parsed_payload = sqlparse.parse(payload)
    except Exception:
        # Just return the input payload if it cannot be parsed to avoid stopping the fuzzing
        return payload
    for t in parsed_payload:
        tokens.extend(list(t.flatten()))

    indices = [idx for idx, token in enumerate(tokens) if token.value in replacements]
    if not indices:
        return payload

    target_idx = random.choice(indices)
    new_payload = "".join([random.choice(replacements[token.value]) if idx == target_idx else token.value for idx, token in enumerate(tokens)])

    return new_payload

"""
NEW FUNCTIONS BELOW
"""
def apply_int_to_ascii(payload: str) -> str:
    """
    Заменяет одно случайное целое число (0-127) в SQL-пейлоуде на вызов ASCII('символ').

    Arguments:
        payload (str): SQL-инъекционный пейлоуд

    Returns:
        str: изменённый пейлоуд
    """
    # Находим все int числа, фильтруем только те,
    # которые соответствуют ASCII-коду
    # и не являются управляемыми (кроме \t и \n)
    candidates = list(re.finditer(r'\b([0-9]{1,3})\b', payload))

    valid = []
    for m in candidates:
        num = int(m.group(1))
        if num == 9:
            char = '\\t'
        elif num == 10:
            char = '\\n'
        elif 32 <= num <= 126:
            char = chr(num)
        else:
            continue
        valid.append((m, char))

    if not valid:
        return payload

    chosen_match, char = random.choice(valid)
    replacement = f"ASCII('{char}')"

    start, end = chosen_match.span()
    new_payload = payload[:start] + replacement + payload[end:]
    return new_payload


def apply_bitwise_or_mutation(payload: str) -> str:
    """
    Заменяет один случайный числовой литерал в SQL-запросе на выражение с побитовым OR,
    корректно разбивая число на две части по битовой маске.
    Например: 6  -> 2 | 4
              5  -> 1 | 4
              1  -> 1 | 0  (единственный установленный бит)
    """
    # Находим все целые числовые литералы
    matches = list(re.finditer(r'\b\d+\b', payload))
    if not matches:
        return payload

    # Выбираем случайную постоянку
    sel = random.choice(matches)
    orig = int(sel.group())
    start, end = sel.span()

    if orig == 0:
        replacement = "(0 | 0)"
    else:
        # Собираем список битов, включённых в orig
        bits = [1 << i for i in range(orig.bit_length()) if orig & (1 << i)]
        # Если в числе только один бит, можно разбить как этот бит | 0
        if len(bits) == 1:
            replacement = f"({orig} | 0)"
        else:
            # Формируем случайную маску: выбираем произвольный непустой поднабор битов, но не весь набор
            subset = set()
            while not subset or subset == set(bits):
                # каждый бит с вероятностью 0.5 включаем в subset
                subset = {b for b in bits if random.random() < 0.5}
            # первая часть — сумма битов из subset, вторая — оставшиеся биты
            part1 = sum(subset)
            part2 = orig & ~part1
            replacement = f"({part1} | {part2})"

    # Собираем новый payload
    return payload[:start] + replacement + payload[end:]


def apply_bitwise_and_mutation(payload: str) -> str:
    """
    Заменяет один случайный числовой литерал в SQL-запросе на выражение с побитовым AND.
    Например: 6 -> 7 & 6
    """
    # Находим все целые числовые литералы
    matches = list(re.finditer(r'\b\d+\b', payload))
    if not matches:
        return payload

    # Выбираем случайный литерал
    sel = random.choice(matches)
    orig = int(sel.group())
    start, end = sel.span()

    if orig == 0:
        # Для 0: 0 & любое_число = 0
        replacement = "(0 & 0)"
    else:
        # Генерируем маску, содержащую все биты оригинала и, возможно, дополнительные
        mask = orig
        for i in range(orig.bit_length()):
            if not (orig & (1 << i)) and random.random() < 0.5:
                mask |= (1 << i)
        replacement = f"({mask} & {orig})"

    # Собираем новый payload
    return payload[:start] + replacement + payload[end:]


def apply_bitwise_xor_mutation(payload: str) -> str:
    """
    Заменяет один случайный числовой литерал в SQL-запросе на выражение с побитовым XOR.
    Например: 6 -> 3 ^ 5
    """
    matches = list(re.finditer(r'\b\d+\b', payload))
    if not matches:
        return payload

    sel = random.choice(matches)
    orig = int(sel.group())
    start, end = sel.span()

    if orig == 0:
        replacement = "(0 ^ 0)"
    else:
        attempts = 0
        while attempts < 10:
            part1 = random.randint(1, orig * 2)
            part2 = orig ^ part1
            if part2 >= 0:
                break
            attempts += 1
        else:
            return payload
        replacement = f"({part1} ^ {part2})"

    return payload[:start] + replacement + payload[end:]


def apply_bitwise_negation_mutation(payload: str) -> str:
    """
    Заменяет один случайный числовой литерал в SQL-запросе на выражение с побитовой инверсией.
    Например: 5 -> ~(-6)
    """
    matches = list(re.finditer(r'\b\d+\b', payload))
    if not matches:
        return payload

    sel = random.choice(matches)
    orig = int(sel.group())
    start, end = sel.span()

    replacement = f"(~(-{orig + 1}))"

    return payload[:start] + replacement + payload[end:]


def apply_redundant_keyword_omission(payload: str):
    """
    Работает только в простых случаях: 'SELECT col AS alias' → 'SELECT col alias'

    Args:
        payload (str): SQL-запрос

    Returns:
        str: модифицированный запрос
    """
    pattern = r'\b(\w+)\s+AS\s+(\w+)\b'
    replaced = re.sub(pattern, r'\1 \2', payload, flags=re.IGNORECASE)
    return replaced


def apply_left_shift_mutation(payload: str) -> str:
    """
    Заменяет один случайный числовой литерал в SQL-запросе на выражение с побитовым сдвигом влево.
    Например: 6 -> 3 << 1
    """
    matches = list(re.finditer(r'\b\d+\b', payload))
    if not matches:
        return payload

    valid_matches = []
    for match in matches:
        num = int(match.group())
        if num == 0:
            valid_matches.append(match)
        else:
            tz = trailing_zeros(num)
            if tz >= 1:
                valid_matches.append(match)
    
    if not valid_matches:
        return payload
    
    sel = random.choice(valid_matches)
    orig = int(sel.group())
    start, end = sel.span()

    if orig == 0:
        # Выбираем случайный сдвиг для нуля
        shift = random.randint(0, 10)
        replacement = f"(0 << {shift})"
    else:
        tz = trailing_zeros(orig)
        max_shift = tz
        shift = random.randint(1, max_shift)
        part1 = orig >> shift
        replacement = f"({part1} << {shift})"

    return payload[:start] + replacement + payload[end:]


def apply_right_shift_mutation(payload: str) -> str:
    """
    Заменяет один случайный числовой литерал в SQL-запросе на выражение с побитовым сдвигом вправо.
    Например: 6 -> 12 >> 1
    """
    matches = list(re.finditer(r'\b\d+\b', payload))
    if not matches:
        return payload

    sel = random.choice(matches)
    orig = int(sel.group())
    start, end = sel.span()

    if orig == 0:
        # Случайный сдвиг для нуля (0 >> shift всегда 0)
        shift = random.randint(0, 10)
        replacement = f"(0 >> {shift})"
    else:
        # Любой сдвиг >= 1, но ограничим диапазон для умеренности
        shift = random.randint(1, 8)
        part1 = orig << shift
        replacement = f"({part1} >> {shift})"

    return payload[:start] + replacement + payload[end:]


def apply_no_spaces_parentheses_mutation(payload: str) -> str:
    """
    Оборачивает в скобки аргумент любого SQL-оператора, исключая комментарии.
    """
    SQL_KEYWORDS = [
        "SELECT", "FROM", "WHERE",
        # "INSERT", "INTO", "VALUES",
        # "UPDATE", "SET", "DELETE", "JOIN", "ON",
        # "GROUP", "HAVING", "ORDER", "LIMIT", "OFFSET", "UNION"
    ]

    # Регулярное выражение: оператор + аргумент
    OPERATOR_RE = re.compile(
        r'(?i)\b(' + '|'.join(SQL_KEYWORDS) + r')\s+'
        r"(('[^']*'|\"[^\"]*\"|[^\s,;()]+))"
    )

    # Регулярки для комментариев
    LINE_COMMENT_RE = re.compile(r'(--[^\n]*|#[^\n]*)(?=\n|$)')
    BLOCK_COMMENT_RE = re.compile(r'/\*.*?\*/', re.DOTALL)

    FORBIDDEN_ARGS = {'*'}

    # Сначала сохраняем позиции комментариев
    comment_spans = []

    for match in LINE_COMMENT_RE.finditer(payload):
        comment_spans.append((match.start(), match.end()))
    for match in BLOCK_COMMENT_RE.finditer(payload):
        comment_spans.append((match.start(), match.end()))

    def in_comment(pos: int) -> bool:
        return any(start <= pos < end for start, end in comment_spans)

    def replacer(match: re.Match) -> str:
        if in_comment(match.start()):
            return match.group(0)  # Не трогаем, если в комментарии

        keyword = match.group(1)
        arg = match.group(2)

        if arg.strip().upper() in FORBIDDEN_ARGS:
            return f"{keyword} {arg}"

        return f"{keyword}({arg})"

    return OPERATOR_RE.sub(replacer, payload)


class SqlFuzzer(object):
    """SqlFuzzer class"""

    strategies = [
        spaces_to_comments,
        random_case,
        swap_keywords,
        swap_int_repr,
        spaces_to_whitespaces_alternatives,
        comment_rewriting,
        change_tautologies,
        logical_invariant,
        reset_inline_comments,
        # New methods
        # apply_mo_chr,
        apply_int_to_ascii,
        apply_bitwise_or_mutation,
        apply_bitwise_and_mutation,
        apply_bitwise_xor_mutation,
        apply_bitwise_negation_mutation,
        apply_left_shift_mutation,
        apply_right_shift_mutation,
        apply_redundant_keyword_omission,
        apply_no_spaces_parentheses_mutation,
    ]

    def __init__(self, payload):
        self.initial_payload = payload
        self.payload = payload

    def fuzz(self):
        strategy = random.choice(self.strategies)

        self.payload = strategy(self.payload)
        # print(self.payload)

        return self.payload

    def current(self):
        return self.payload

    def reset(self):
        self.payload = self.initial_payload
        return self.payload
