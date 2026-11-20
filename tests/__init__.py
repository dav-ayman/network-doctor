import os
import tempfile

# Keep the login guard, backups and captures of test runs away from the real ~/.network-doctor.
os.environ["NETDOC_HOME"] = tempfile.mkdtemp(prefix="netdoc-test-")
os.environ["NETDOC_PASSWORD"] = "test-pass"
