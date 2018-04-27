#!/usr/bin/env python2
import struct
import math
import dpkt
import socket
import numpy as np
from collections import Counter
from frequency import *

def substitute(attack_payload, substitution_table):
    # Using the substitution table you generated to encrypt attack payload
    # Note that you also need to generate a xor_table which will be used to decrypt the attack_payload
    # i.e. (encrypted attack payload) XOR (xor_table) = (original attack payload)
    b_attack_payload = bytearray(attack_payload)
    result = []
    xor_table = []
    # Based on your implementattion of substitution table, please prepare result and xor_table as output
    
    # For each byte in attack payload,
    for byte_in_att in b_attack_payload:

        print(byte_in_att)
        # Get the list for the character from the substition table
        char_temp = chr(byte_in_att)
        char_list = substitution_table[char_temp]
        
        # If the list is only one character, 
        if len(char_list) == 1:
            # Substitute that single character in
            char_chosen = char_list[0][0]
        # Otherwise, choose one character at random from the list
        else:
            # By first going through each choice in list
            chars_to_select = []
            chars_freqs = []
            for char_choice in char_list:
                # And adding it to an array 
                chars_to_select.append(char_choice[0])
                # and add its frequency to a list
                chars_freqs.append(char_choice[1])

            # Spread the frequencies between 1 (e.g. 0.1, 0.3 and 0.4 would go
            # 0.125, 0.375 and 0.5)
            # First add up all of the frequecies
            total = 0
            for next in chars_freqs:
                total += next
            # then multiply each item by 1/total
            for cnt in range(0,len(chars_freqs)):
                chars_freqs[cnt] = chars_freqs[cnt] * (1/total)

            # Then choose one letter at random, based on the frequency
            char_chosen = np.random.choice(chars_to_select, p=chars_freqs)
    
        # add it to the result.
        result.append(char_chosen)

    # Create a XOR table

    table_cnt = 0
    
    # For each character in the substitution table i.e. Find a list and then
    # loop through the list...
    for att_repl_char, sub_list in substitution_table.iteritems():
        for sub_char_tup in sub_list: 

            # Loop, increasing a counter, until result is found - brute force!
            found = False
            xor_cnt = 0
            while found == False:
                # If correct result found, finish the loop
                # i.e. if the current counter XOR next substitution character == the
                # attack character...
                print("sub_char_tup[0] = " + str(ord(sub_char_tup[0])))
                print("att_repl_char = " + str(ord(att_repl_char)))
                print("result = " + str(xor_cnt ^ ord(sub_char_tup[0])))
                res = xor_cnt ^ ord(sub_char_tup[0])
                #xor_cnt += 1
                if res == ord(att_repl_char):
                    found = True
                # else continue the loop
                else:
                    xor_cnt += 1

            # Add result to XOR table
            xor_table.append(xor_cnt)
        table_cnt += 1
        print("XOR Table")
        print(xor_table)
        input("...")

    return (xor_table, result)

def getSubstitutionTable(artificial_payload, attack_payload):
    # You will need to generate a substitution table which can be used to encrypt the attack body by replacing the most frequent byte in attack body by the most frequent byte in artificial profile one by one

    # Note that the frequency for each byte is provided below in dictionay format. Please check frequency.py for more details
    artificial_frequency = frequency(artificial_payload)
    attack_frequency = frequency(attack_payload)

    sorted_artificial_frequency = sorting(artificial_frequency)
    sorted_attack_frequency = sorting(attack_frequency)

    # Your code here ...
    
    # Create an empty dictionary for the substitute table whose keys are 
    # characters and who values are list of tuples.  The list of tuples 
    # are characters with floats.
    substitution_table = {}
    
    # Copy each character into the substitute table keys from the sorted 
    # attack frequency data structure.
    for char_tup in sorted_attack_frequency:
        substitution_table[char_tup[0]] = []

    # For the first m characters, and first n, (Using m and n as a tuples here)
    for m, n in zip(sorted_attack_frequency, sorted_artificial_frequency):
        # Map attack characters to normal characters.
        substitution_table[m[0]] = [n]     

    print("-----------------------")
    #substitution_table['!'].append(('b',0))
    print(substitution_table) 
    # Create counter for size of m to go to size of n
    m_plus_n_cnt = len(substitution_table)

    # Create a temporary table of all of the character left from the 
    # artificial table
    chars_left =[]

    for cnt in range(m_plus_n_cnt, len(sorted_artificial_frequency)):
        chars_left.append(sorted_artificial_frequency[cnt])
    
  
    # For each of the m+nth characters in the artificial table:
    for art_char in chars_left:
        # Hold the largest of the substitute table subsub ratios
        highest_ratio = 0           
        # ... and it's character tuple
        highest_ratio_char = ()
   
        # For each of the characters in the substition table
        for att_char in sorted_attack_frequency:
            sub_sub_total = 0
            sub_ratio = 0

            # For each of the tuples in the substituion table character list
            for subst_char in substitution_table[att_char[0]]:
                sub_sub_total += subst_char[1]
            
            # Now create the ratio of current subst table char and compare it
            # with the highest. If higher, set as new
            sub_ratio = att_char[1] / sub_sub_total
            print("sub_ratio = " + str(sub_ratio))
            print("highest Ratio = " + str(highest_ratio))

            if sub_ratio > highest_ratio: 
                highest_ratio = sub_ratio
                highest_ratio_char = att_char
                print("rat = " + str(sub_ratio))
        
        substitution_table[highest_ratio_char[0]].append(art_char)
    print("substitution_table = ")
    print(substitution_table)
    
    # You may implement substitution table in your way. Just make sure it can be used in substitute(attack_payload, subsitution_table)
    return substitution_table

def getAttackBodyPayload(path):
    f = open(path)
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        if socket.inet_ntoa(ip.dst) == "192.150.11.111": # TASK: Add in the destination address for your attack payload in quotes
            tcp = ip.data
            if tcp.data == "":
                continue
            return tcp.data.rstrip()

def getArtificialPayload(path):
    f = open(path)
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        if tcp.sport == 80 and len(tcp.data) > 0:
            return tcp.data
