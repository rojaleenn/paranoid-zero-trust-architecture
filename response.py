# response.py
from datetime import datetime
from app import log_forensic_event  # Make sure this matches your app.py import

# Keep track of nodes that have already been isolated
isolated_nodes = set()

def isolate_node(node_id):
    """
    Isolate a node due to suspicious activity.
    Logs the event to the forensics system and prints a message.
    """
    if node_id not in isolated_nodes:
        isolated_nodes.add(node_id)
        # Log the isolation event for forensics
        log_forensic_event(node_id, "Node isolated due to suspicious activity")
        # Print to console for live monitoring
        print(f"🚨 Node {node_id} has been isolated!")

