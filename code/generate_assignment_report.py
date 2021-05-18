import os
import yaml

#download all vulnerabilities statements to local machine
def downloadStatements():
    #if statements not downloaded
    if not os.path.isdir("./data/statements"):
        # Cloning to data folder
        os.system("git clone --branch vulnerability-data --depth 1 --filter=blob:none --sparse https://github.com/SAP/project-kb data") 
        os.chdir("./data")
        os.system("git sparse-checkout set statements")
        os.chdir("..")

def loadData():
    all_CVE_statements_list = []

    #correct error in statement.yaml in CVE-2020-13954
    file = open("./data/statements/CVE-2020-13954/statement.yaml", 'r')
    content = file.readlines()
    file.close()

    if(content[1] == "- links:\n"):
        file = open("./data/statements/CVE-2020-13954/statement.yaml", 'w')
        content[1] = "links:\n"
        file.write("".join(content))
        file.close()


    #read all yaml files
    for folder in os.listdir("./data/statements"):
        if "CVE" in folder :
            # Read YAML file
            with open("./data/statements/" + folder + "/statement.yaml", 'r') as stream:
                data_loaded = yaml.safe_load(stream)
            all_CVE_statements_list.append(data_loaded)

    return all_CVE_statements_list

#generate 3 lists for the 3 categories of statements
def generateReportLists(all_CVE_statements_list):
    multiple_fixes = []
    multiple_fixes_different_commits_nb = []
    no_fixes = []
    
    for statement in all_CVE_statements_list:
        fixes = statement.get("fixes", [])

        if len(fixes) > 1:
            #statement has multiple fixes
            multiple_fixes.append(statement)

            commits_nb = []
            diff_nbs = True

            for fix in fixes :
                fix_commit_nb = len(fix["commits"])

                if fix_commit_nb in commits_nb:
                    diff_nbs = False
                    break
                else:
                    commits_nb.append(fix_commit_nb)
            
            if diff_nbs:
                #statement has multiple fixes with different number of commits for each
                multiple_fixes_different_commits_nb.append(statement)


        if len(fixes) == 0:
            #statement has no fixes 
            no_fixes.append(statement)
    
    return multiple_fixes, multiple_fixes_different_commits_nb, no_fixes


def printReport(multiple_fixes, multiple_fixes_different_commits_nb, no_fixes):
    
    print("There are " + str(len(multiple_fixes)) + " statements that have multiple fixes :")
    for statement in multiple_fixes:
        print("    Statement id : " + statement["vulnerability_id"] + ", " + str(len(statement.get("fixes", []))) + " fixes :")
        fix_nb = 1
        for fix in statement["fixes"]:
            print("     Fix " + str(fix_nb) + ": " + str(len(fix["commits"])) + " commit(s)")
            fix_nb += 1

    print(" ")

    print("There are " + str(len(multiple_fixes_different_commits_nb)) + " statements that have multiple fixes with a different number of commits in each :")
    for statement in multiple_fixes_different_commits_nb:
        print("    Statement id : " + statement["vulnerability_id"] + ", " + str(len(statement.get("fixes", []))) + " fixes :")
        fix_nb = 1
        for fix in statement["fixes"]:
            print("     Fix " + str(fix_nb) + ": " + str(len(fix["commits"])) + " commit(s)")
            fix_nb += 1

    print(" ")

    print("There are " + str(len(no_fixes)) + " statements that have no fixes :")
    for statement in no_fixes:
        print("    Statement id : " + statement["vulnerability_id"])

    return

#script
downloadStatements()
all_CVE_statements_list = loadData()
multiple_fixes, multiple_fixes_different_commits_nb, no_fixes = generateReportLists(all_CVE_statements_list)
printReport(multiple_fixes=multiple_fixes, multiple_fixes_different_commits_nb=multiple_fixes_different_commits_nb, no_fixes=no_fixes)



def test_downloaded():
    print("tests the download of the vulnerability statements")
    downloadStatements()
    assert os.path.isdir("./data/statements")

def test_data_loaded():
    all_CVE_statements_list = loadData()
    assert len(all_CVE_statements_list) != 0

def test_multiple_fixes_list():
    downloadStatements()
    all_CVE_statements_list = loadData()
    multiple_fixes, multiple_fixes_different_commits_nb, no_fixes = generateReportLists(all_CVE_statements_list)

    for statement in multiple_fixes:
        assert len(statement["fixes"]) > 1

def test_multiple_fixes_different_commits_nb_list():
    downloadStatements()
    all_CVE_statements_list = loadData()
    multiple_fixes, multiple_fixes_different_commits_nb, no_fixes = generateReportLists(all_CVE_statements_list)

    for statement in multiple_fixes_different_commits_nb:
        assert len(statement["fixes"]) > 1

        commits_nb = []
        for fix in statement["fixes"]:
            assert not(len(fix["commits"]) in commits_nb)
            commits_nb.append(len(fix["commits"]))

def test_no_fixes_list():
    downloadStatements()
    all_CVE_statements_list = loadData()
    multiple_fixes, multiple_fixes_different_commits_nb, no_fixes = generateReportLists(all_CVE_statements_list)

    for statement in no_fixes:
        assert len(statement.get("fixes", [])) == 0


        