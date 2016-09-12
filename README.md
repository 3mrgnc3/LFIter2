# LFIter2 (Currently in Alpha)
### LFIter2 Local File Include (LFI) MultiTool - Auto File Extractor &amp; Username Bruteforcer

    Many Web Servers are vulnerable to remote directory traversal      
    attacks.                                                           
                                                                       
    I created this tool to automatically extract a list of known        
    interesting files based on a wordlist and be able to bruteforce
    usernames on an affected system [still to do :P].                             
                                                                       
       FEATURES:
       
        1. Support For Multiple Server Types.
        2. Print Remote Files in local Terminal.
        3. Batch Extract Files Using A Wordlist.
        4. Brute Force Usernames Using A Wordlist. [TO DO!]             
                                                                       
    I hope others may find this usefull during pentests. I have 
    chosen to use subprocess to call curl to perform web requests. 
    I Initially tried to use python-requests and libcurl, but was 
    having major issues getting self signed certs for https & socks 
    proxies working using these. 
                                                                      
    Curl just works :D As long as its installed and working you 
    should be able to run this script.
                                                                       
    Collected Files Are Saved In the ./[host-ip]-files/ Directory      
    --------------------------------------------------------------            
     ref:                                                              
     https://owasp.org/index.php/Testing_for_Local_File_Inclusion      
    --------------------------------------------------------------     
                                                                       
    TARGETS: (-trgt)                                                   
                                                                       
        [ zervit = Zervit 0.4 for Windows ]
        [ cuppa  = CUPPA CMS vb.0..1 for FreeBSD ]
        [ wbm128 = Webmin 1.28 for Fedora Core 4 ]                     

    ===Examples===================================================     
    lfitr2.py 172.16.10.1 -list win-paths.txt                          
    lfitr2.py 172.16.10.1 -path /windows/system32/drivers/etc/hosts    
    lfitr2.py 172.16.10.1 -list win-paths.txt -port 8008               
    lfitr2.py 172.16.10.1 -path /BOOT.INI -out /root/report/host       
    ==============================================================                                                                          
