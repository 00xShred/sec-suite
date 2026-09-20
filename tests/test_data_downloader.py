from utils import data_downloader


def test_download_file_sets_request_timeout(monkeypatch, tmp_path):
    calls = {}

    class Response:
        headers = {"content-length": "0"}

        def raise_for_status(self):
            pass

        def iter_content(self, chunk_size):
            return iter(())

    def fake_get(*args, **kwargs):
        calls["kwargs"] = kwargs
        return Response()

    monkeypatch.setattr(data_downloader.requests, "get", fake_get)

    data_downloader.download_file("https://example.test/file.txt", str(tmp_path / "file.txt"))

    assert calls["kwargs"]["timeout"] == (10, 30)
