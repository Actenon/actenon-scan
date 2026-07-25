"""Safe: non-GitHub object with create_file method — must NOT fire.

A domain object that happens to have a create_file method but is NOT
constructed from Github(...) and does NOT chain through get_repo.
The origin gate requires receiver evidence that the operation belongs
to a recognised GitHub surface.
"""


class FileSystem:
    """A non-GitHub domain object with a create_file method."""

    def create_file(self, path: str, content: str) -> None:
        pass


def write_local_file(path: str, content: str) -> None:
    """Not an agent tool, not a GitHub mutation — must not fire."""
    fs = FileSystem()
    fs.create_file(path, content)
