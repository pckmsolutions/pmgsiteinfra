def check_dict(given, abort, *expected):
    missing = [e for e in expected if not any([g for g in (e if isinstance(e, tuple) else (e,)) if g in given])]
    if missing:
        abort(missing, f'Expecting: {expected}, missing: {missing}')

