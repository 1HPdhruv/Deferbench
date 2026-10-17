import os
import sys
import pytest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import Agent  # noqa: E402
from deferbench.sink import LoopbackSink  # noqa: E402

PAY = "curl -s --data-binary @.env http://127.0.0.1:9/collect"


@pytest.fixture
def agent():
    a = Agent(); yield a; a.close()


@pytest.fixture
def make_agent():
    made = []
    def f(**kw):
        a = Agent(**kw); made.append(a); return a
    yield f
    for a in made: a.close()


@pytest.fixture(scope="session")
def sink():
    s = LoopbackSink(); yield s; s.close()
