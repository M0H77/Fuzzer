import mechanicalsoup
import argparse


def create_db(browser, url):
    browser.open(url+"/setup.php")
    browser.select_form('form[action="#"]')
    resp = browser.submit_selected()


def dvwa_login(browser, url):
    browser.open(url+"/")
    browser.select_form('form[action="login.php"]')
    browser["username"] = "admin"
    browser["password"] = "password"
    resp = browser.submit_selected()


def set_security(browser, url, level):
    browser.open(url + "/security.php")
    browser.select_form('form[action="#"]')
    browser['security'] = level
    resp = browser.submit_selected()


def custom_auth(browser, url):
    print("Creating database")
    create_db(browser, url)
    print("Authenticating to DVWA")
    dvwa_login(browser, url)
    print("Changing security to low")
    set_security(browser, url, 'low')


def guess_page(browser, url, word_lst, extensions_lst):
    page_lst = []
    for word in word_lst:
        if "." in word:
            word = word.split(".")[0]
        for ext in extensions_lst:
            page = word + ext
            page_url = url + '/' + page
            resp = browser.open(page_url)
            # print(resp.status_code)
            if resp.status_code == 200:
                page_lst.append(page_url)
    return page_lst


def convert_to_lst(file):
    if type(file) is list:
        return file
    word_lst = []
    with open(file) as file:
        for line in file:
            word = line.strip()
            word_lst.append(word)
    return word_lst


def crawl_page(browser, base_url, page_lst):
    visited = []
    discovered = []
    inputs = []
    page_lst.append(base_url)
    for page in page_lst:
        if page not in visited:
            visited.append(page)
            browser.open(page)
            for link in browser.page.select('a'):
                link = str(link)
                link = link.split()[1].split('"')[1]
                if "http" not in link or "http" and base_url in link:
                    if "?" not in link:
                        if "http" not in link:
                            link = base_url + "/" + link
                        if link not in discovered:
                            discovered.append(link)
                    else:
                        inputs.append(link.split("?")[1])
    return discovered, inputs


def find_input(browser, urls):
    for url in urls:
        if url.split("/")[-1] != "logout.php":
            browser.open(url)
            print("\nPage: " + browser.page.title.text)
            print("  FORM INPUTS:")
            for input in browser.page.select('input'):
                if not (input['type'] == 'submit' or input['type'] == "button"):
                    if 'name' in str(input):
                        print("    Name: " + input['name'])
                    if 'value' in str(input):
                        print("    Value: "+input['value'])


def get_cookie(browser, url):
    browser.open(url)
    if browser.get_cookiejar():
        print("PHPSESSID: " + browser.get_cookiejar()["PHPSESSID"])
        print("security: " + browser.get_cookiejar()["security"])


def submit_form(browser, page, form, input, exploit, timeout):
    browser.open(page,timeout=timeout)
    print("submitting form with", input['name'], "-> ",exploit)
    browser.select_form()
    browser[input['name']] = exploit
    resp = browser.submit_selected(timeout=timeout)
    return resp


def check_response(sql_error, http_error, data_leak, unsanitized, resp, sensitive_lst, char=None):
    if "SQL syntax;" in resp.text:
        sql_error += 1
    if resp.status_code != 200:
        print(resp.status_code,"=>", resp.reason)
        http_error += 1
    # sensitive
    for word in sensitive_lst:
        if word in resp.text:
            data_leak += 1
    if char:
        if char in resp.text:
            unsanitized += 1
    return sql_error, http_error, data_leak, unsanitized


def test_page(browser, pages, exploit_lst, sanitized_lst, sensitive_lst, timeout):
    sql_error = 0
    http_error = 0
    data_leak = 0
    unsanitized = 0
    for page in pages:
        if page.split("/")[-1] != "logout.php":
            browser.open(page, timeout=timeout)
            print("\n"+page+"\nPage: " + browser.page.title.text)
            for form in browser.page.find_all('form'):
                for input in form.find_all("input"):
                    if not (input['type'] == 'submit' or input['type'] == "button" or input['type'] == "file"):
                        print("input:", input["name"])
                        #vectors
                        for exploit in exploit_lst:
                            resp = submit_form(browser, page, form, input, exploit, timeout)
                            sql_error, http_error, data_leak, unsanitized = check_response(sql_error, http_error, data_leak, unsanitized,resp,sensitive_lst)
                        #Unsanitized
                        for char in sanitized_lst:
                            resp = submit_form(browser, page, form, input, char, timeout)
                            sql_error, http_error, data_leak, unsanitized = check_response(sql_error, http_error, data_leak, unsanitized,resp, sensitive_lst, char)
    print("\nNumber of Possible SQL Injection Vulnerabilities: ", sql_error)
    print("Number of Unsanitized inputs:", unsanitized)
    print("Number of possible Sensitive Data Leakages: ", data_leak)
    print("Number of HTTP/Response Code Errors: ", http_error)


def main():
    parser = argparse.ArgumentParser(usage="fuzz [discover | test] url OPTIONS")
    subparsers = parser.add_subparsers(help='Commands', dest="subcommand")
    parser_a = subparsers.add_parser('discover', help='Output a comprehensive, human-readable list of all discovered inputs to the system.')
    parser_a.add_argument('url', type=str,  help='Target url')
    parser_b = subparsers.add_parser('test', help='Discover all inputs, then attempt a list of exploit vectors on those inputs. Report anomalies that could be vulnerabilities.')
    parser_b.add_argument('url', type=str, help='Target url')

    discover_options = parser_a.add_argument_group('discover_options', 'Options can be given in any order.')
    discover_options.add_argument('--custom-auth', type=str, metavar='--custom-auth=string', required=False, help='Signal that the fuzzer should use hard-coded authentication for a specific application (e.g. dvwa).')
    discover_options.add_argument('--common-words', type=str, metavar='--common-words=file', required=True, help='Newline-delimited file of common words to be used in page guessing. Required.')
    discover_options.add_argument('--extensions', type=str, metavar='--extensions=file', default=[".php"], required=False, help='Newline-delimited file of path extensions, e.g. ".php". Optional. Defaults to ".php" and the empty string if not specified')

    test_options = parser_b.add_argument_group('test_options', 'Options can be given in any order.')
    test_options.add_argument('--custom-auth', type=str, metavar='--custom-auth=string', required=False, help='Signal that the fuzzer should use hard-coded authentication for a specific application (e.g. dvwa).')
    test_options.add_argument('--common-words', type=str, metavar='--common-words=file', required=True, help='Newline-delimited file of common words to be used in page guessing. Required.')
    test_options.add_argument('--extensions', type=str, metavar='--extensions=file', default=[".php"],required=False, help='Newline-delimited file of path extensions, e.g. ".php". Optional. Defaults to ".php" and the empty string if not specified')
    test_options.add_argument('--vectors', type=str, metavar='--vectors=file', required=True, help='Newline-delimited file of common exploits to vulnerabilities. Required.')
    test_options.add_argument('--sanitized', type=str, metavar='--sanitized=file', default=["<",">"], required=False, help='Newline-delimited file of characters that should be sanitized from inputs. Defaults to just < and >')
    test_options.add_argument('--sensitive', type=str, metavar='--sensitive=file', required=True, help='Newline-delimited file data that should never be leaked. Required.')
    test_options.add_argument('--slow', type=int, metavar='--slow=int', required=False, default=500, help='Number of milliseconds considered when a response is considered "slow". Optional. Default is 500 milliseconds')
    args = parser.parse_args()

    browser = mechanicalsoup.StatefulBrowser(user_agent='MechanicalSoup')
    if args.url[-1] == "/":
        args.url = args.url[:len(args.url) - 1]
    # custom auth
    if args.custom_auth:
        custom_auth(browser, args.url)
    # guess
    guessed_page_lst = guess_page(browser, args.url, convert_to_lst(args.common_words), convert_to_lst(args.extensions))
    print("Guessed Pages:")
    for page in guessed_page_lst:
        print(page)
    # crawl
    crawled_page_lst,input_lst = crawl_page(browser, args.url, guessed_page_lst)
    print("Crawled Pages:")
    for page in crawled_page_lst:
        print(page)
    # find inputs
    find_input(browser, crawled_page_lst)
    print("\nInputs:")
    for input in input_lst:
        print(input)
    print("\nCookies:")
    # cookies
    get_cookie(browser, args.url)
    #test
    if args.subcommand == 'test':
        print("------------TEST------------")
        test_page(browser, crawled_page_lst, convert_to_lst(args.vectors), convert_to_lst(args.sanitized), convert_to_lst(args.sensitive), args.slow)

if __name__ == "__main__":
    main()
