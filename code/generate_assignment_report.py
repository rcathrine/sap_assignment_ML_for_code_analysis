
import sys
import os

#download all vulnerabilities statements to local machine
def download_statements():
    # Cloning to data folder
    os.system("git clone --branch vulnerability-data --depth 1 --filter=blob:none --sparse https://github.com/SAP/project-kb data") 
    os.chdir("./data")
    os.system("git sparse-checkout set statements")
    os.chdir("./data")


def test_download():
    print("tests the download of the vulnerability statements")
    assert os.path.isdir("./data/statements")