

def test_positive_relay_respond_trigger_sha256(relay_api):
    """ Test relay respond trigger api mock for sha256 in Qualys

    ID: CCTRI-744-4c96ad24-5a16-449b-9120-0af449d546c6

    Steps:
        1. Send request with sha256 type to endpoint respond trigger

    Expectedresults:
        1. Check data in body respond

    Importance: Critical
    """
    action_id = "blacklist-observable"
    observable_value = (
        "01f30887a828344f6cf574bb05bd0bf571fc35979a3032377b95fb0d692b8061")
    observable_type = "sha256"

    # Get sightings
    observables = [{"action-id": action_id,
                    "observable_type": observable_type,
                    "observable_value": observable_value}]
    sightings = relay_api.respond_trigger(
        payload=observables).json()

    # Check respond data
    assert sightings['data']['status'] == 'failure'
