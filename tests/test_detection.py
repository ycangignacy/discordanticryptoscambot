from detection import check_text, matched_domain, matched_term


def test_keywords_are_case_insensitive_with_word_boundaries():
    assert matched_term("FREE CRYPTO giveaway!", ["free crypto giveaway"])
    assert matched_term("classifier", ["ass"]) is None


def test_domain_matches_subdomains_but_not_lookalikes():
    assert matched_domain("https://login.fake-example.com/a", ["fake-example.com"])
    assert matched_domain("https://fake-example.com.evil.org", ["fake-example.com"]) is None
    assert matched_domain("www.fake-example.com/x", ["fake-example.com"])


def test_check_text_reports_reason():
    assert check_text("send crypto to receive prizes", ["send crypto to receive"], [], [])
    assert check_text("ordinary message", [], [], []) is None
