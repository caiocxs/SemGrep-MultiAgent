import os
import sys

# Support direct execution as well as package imports
if __package__ is None or __package__ == "":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from src.agents import agents_general, code_agent
else:
    from .agents import agents_general, code_agent

__all__ = ["agents_general", "code_agent", "main"]


def main():
    code_agent.init_agent()
    code_agent.start_code_analysis()


if __name__ == "__main__":
    main()
