#!/usr/bin/python

from subprocess import call
import sys
import os

###########################################################################
#                          TESTS FOR ENCRYPTFS                            #
###########################################################################

# To run tests please run: python test_driver.py {test #}
# If test number is not provided, it will run all tests

def test1():
    print "\nTEST #1: Making a file\n"
    
    put = os.system("python client.py put -n 'test1.txt' -d 'asdfasf' \
                                      > td_files/1.out")
    assert(put == 0)

    f = open("td_files/1.out", "r")
    output = f.read()

    assert(output != "")
    
    f.close()

    print "\nPASS\n"
    


def test2():

    print "\nTEST #2: Getting a file\n"

    put = os.system("python client.py put -n 'test2.txt' -d 'asdfasdf'")
    assert(put == 0)
    
    get = os.system("python client.py get -n 'test2.txt' --t > td_files/2.out")
    assert(get == 0)
    
    f = open("td_files/2.out", "r")
    expected = "asdfasdf"  
    
    output = f.read()
    print "output", output
    sp = output.split("\n")[5]
    print "sp", sp

    assert(sp == expected)
    
    f.close()
    
    print "\nPASS\n"



def test3():

    print "\nTEST #3: Getting file that was corrupted by server\n"

    #os.system("./resetserver.sh; ./resetclient.sh")

    put = os.system("python client.py put -n 'test3.txt' -d 'asdfasdf'  \
                                      > td_files/3.out")
    
    os.system("ls userdata > td_files/ls3.out")
    
    ls = open("td_files/ls3.out", "r")
    fname = ls.read().strip("\n")
    
    f = open("userdata/"+fname, "r+")
    f.write("asdfasdfasdf")
    f.read()
    f.close()

    get = os.system("python client.py get -n 'test3.txt' --t")
    assert(get == 0)

    print "\nPASS\n"



def test4():

    print "\nTEST #4: Writing to a file using capabilites\n"

    os.system("python client.py put -n 'test4.txt' -d 'asdfasdf' \
                                > td_files/4.out")
    
    f = open("td_files/4.out", "r")
    output = f.read()
    
    write_cap = output.split("is:")[1].split("\n")[0].strip()

    cap = os.system("python client.py put -c "+write_cap+ " -d ';lkj;lkj'")

    assert(cap == 0)

    os.system("python client.py get -n 'test4.txt' --t > td_files/4-1.out")
    g = open("td_files/4-1.out")
    
    newtext = g.read().split("\n")[5]
    
    assert(newtext == ';lkj;lkj')

    g.close()
    f.close()
    
    print "\nPASS\n"



def test5():

    print "\nTEST #5: Reading a file using capabilites\n"
    
    os.system("python client.py put -n 'test4.txt' -d 'asdfasdf' \
                                > td_files/5.out")
    
    f = open("td_files/5.out", "r")
    output = f.read()
    
    read_cap = output.split("is:")[2].split("\n")[0].strip()

    print output
    print read_cap
    
    cap = os.system("python client.py get -c "+read_cap+ " --t")

    print "\nPASS\n"



def test6():

    print "\nTEST #6: Checking if other users can access files\n"

    os.system("python client.py put -n 'test6.txt' -d 'asdfasdf' \
                                > td_files/6.out")
    
    os.system("sudo su Tito")
    get = os.system("python client.py get -n 'test5.txt' --t")
    
    assert(get == 0)

    print "\nPASS\n"



#os.system("rm td_files/*; ./resetserver.sh; ./resetclient.sh")
if len(sys.argv) != 1:
    if sys.argv[1] == '1':
        test1()
    if sys.argv[1] == "2":
        test2()
    if sys.argv[1] == "3":
        test3()
    if sys.argv[1] == "4":
        test4()
    if sys.argv[1] == "5":
        test5()
    if sys.argv[1] == "6":
        test6()
else:
    test1()
    test2()
    test3()
    test4()
    test5()
    test6()
