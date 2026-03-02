from nids.flows import FlowStats


def test_flow_vector_shape():
    st = FlowStats(first_seen=1.0, last_seen=1.0)
    st.add_packet(size=100, flags=0x02, is_tcp=True)
    st.add_packet(size=150, flags=0x10, is_tcp=True)
    v = st.to_vector()
    assert len(v) == 12
    assert v[0] == 2.0
