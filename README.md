# Polymorphic-Blending-Attack
We assume that the attacker has a specific payload (attack payload) that he would like
to blend in with the normal traffic. Also, we assume that the attacker has access to one
packet (artificial profile payload) that is normal and is accepted as normal by the PAYL
model.  
The attacker’s goal is to transform the byte frequency of the attack traffic so that is
matches the byte frequency of the normal traffic, and thus bypass the PAYL model.  
○ Code provided: ​ Please look at the Polymorphic blend directory. All files  
(including attack payload) for this task should be in this directory.  
○ How to run the code: ​ Run ​ task1.py  
○ Main function: ​ task1.py ​ contains all the functions that are called.  
○ Output: ​ The code should generate a new payload that can successfully bypass  
the PAYL model that you have found above (using your selected parameters).   
The new payload (output) is shellcode.bin + encrypted attack body + XOR  
table + padding. Please refer to the paper for full descriptions and definitions of  
Shellcode, attack body, XOR table and padding. The Shellcode is provided.  
Substitution table: ​ We provide the skeleton for the code needed to generate a  
substitution table, based on the byte frequency of attack payload and artificial  
profile payload. According to the paper the substitution table has to be an array of  
length 256. For the purpose of implementation, the substitution table can be e.g.a  
python dictionary table. We ask that you complete the code for the substitution  
function. You are free to create this table with one-to-one or one-to-many  
mapping as per your choice.  
○ Padding: ​ Similarly we have provided a skeleton for the padding function and we  
are asking you to complete the rest.  
○ Main tasks: ​ Please complete the code for the s ​ ubstitution.py ​ and ​ padding.py ​ , to  
generate the new payload.  
○ Deliverables: ​ Please deliver your code for the substitution and the padding, and  
the output of your code. Please see section deliverables.  
