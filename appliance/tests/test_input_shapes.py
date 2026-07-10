"""C1/C2: no input shape may bypass the field walker (fail-open). input_text/output_text aliases, bare-string
content arrays, and unknown block types must all surface their free text for redaction."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import egress_proxy as E  # noqa: E402


def _texts(body):
    return [f.text for f in E.extract_text_fields(body)]


def test_input_text_alias_extracted():
    b = {'messages': [{'role': 'user', 'content': [{'type': 'input_text', 'text': 'PII here'}]}]}
    assert 'PII here' in _texts(b)


def test_output_text_alias_extracted():
    b = {'messages': [{'role': 'assistant', 'content': [{'type': 'output_text', 'text': 'PII out'}]}]}
    assert 'PII out' in _texts(b)


def test_array_of_strings_content_extracted():
    b = {'messages': [{'role': 'user', 'content': ['leak A', 'leak B']}]}
    t = _texts(b)
    assert 'leak A' in t and 'leak B' in t


def test_unknown_block_type_recursed():
    b = {'messages': [{'role': 'user', 'content': [{'type': 'future_block', 'text': 'novel PII'}]}]}
    assert any('novel PII' in x for x in _texts(b))


def test_system_array_input_text_extracted():
    b = {'system': [{'type': 'input_text', 'text': 'sys PII'}], 'messages': []}
    assert 'sys PII' in _texts(b)


def test_binary_block_not_recursed_as_text():
    # an image block's base64 must NOT be surfaced as a scannable text field
    b = {'messages': [{'role': 'user', 'content': [{'type': 'image', 'source': {'data': 'AAAA'}}]}]}
    assert 'AAAA' not in _texts(b)


def test_chat_image_url_block_is_opaque():
    # The Chat Completions image part ({type:'image_url', image_url:{url:'data:...'}}) is binary/out-of-scope:
    # neither the data-URI blob nor the URL string may be surfaced as a scannable field (no over-rewrite).
    # Checked on the real OpenAI extractor (its actual route) AND the Anthropic walker (sets kept in sync).
    import openai_adapter  # noqa: E402
    data_uri = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB'
    b = {'messages': [{'role': 'user', 'content': [
        {'type': 'image_url', 'image_url': {'url': data_uri}}]}]}
    for extract in (openai_adapter.extract_text_fields_openai, E.extract_text_fields):
        leaked = [f.text for f in extract(b)]
        assert all(data_uri not in x for x in leaked), (extract.__name__, leaked)
        assert all('image/png' not in x for x in leaked), (extract.__name__, leaked)
