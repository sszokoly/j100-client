"""Run the J100 command line interface as a Python module."""


def run() -> None:
    from .cli import main

    main()


if __name__ == "__main__":
    run()
