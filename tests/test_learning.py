from io import BytesIO

from PIL import Image, ImageDraw

from scam_learning import ScamLearning


def sample_image() -> bytes:
    image = Image.new("RGB", (96, 96), "white")
    drawing = ImageDraw.Draw(image)
    drawing.rectangle((8, 10, 75, 45), fill="red")
    drawing.line((5, 90, 90, 50), fill="black", width=5)
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def test_learning_persists_matches_and_unlearns(tmp_path):
    raw = sample_image()
    learner = ScamLearning(tmp_path, False, 8, 0.9)
    identifier, created = learner.learn(raw, "test", "test:1")
    assert created
    assert learner.learn(raw, "test", "test:1") == (identifier, False)
    reloaded = ScamLearning(tmp_path, False, 8, 0.9)
    assert identifier in reloaded.match(raw)
    assert reloaded.unlearn(identifier)
    assert reloaded.match(raw) is None
