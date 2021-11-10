import pytest
import random

from tests.functional.library.constants import OBSERVABLE_DICT


@pytest.mark.parametrize("relay_endpoint", (
        "health",
        "refer_observables",
        "observe_observables",
))
def test_positive_relay_api(relay_endpoint, relay_api):
    """ Test relay api mock in Qualys

    ID: CCTRI-744-e78ccca8-ad80-4c20-a2ea-11a254f0bc35

    Steps:
        1. Send request to endpoint

    Expectedresults:
        1. Status code == 200

    Importance: Critical
    """
    observable_value, observable_type = random.choice(
        list(OBSERVABLE_DICT.items()))
    observables = [{'value': observable_value, 'type': observable_type}]
    # Check status
    assert relay_api.__getattribute__(relay_endpoint)(
        payload=observables).status_code == 200
