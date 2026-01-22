# ABOUTME: Entry point for running ping_sweep as a module.
# ABOUTME: Enables `python -m ping_sweep` invocation.

from .cli import main

if __name__ == "__main__":
    main()
