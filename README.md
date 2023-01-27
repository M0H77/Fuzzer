# fuzzer
- SWEN 331 Fuzzer Project

## Getting started
Install MechanicalSoup
- pip3 install MechanicalSoup
## How to Run
fuzz [discover | test] url OPTIONS
## Help
- python3 fuzz.py -h
- python3 fuzz.py discover -h
- python3 fuzz.py test -h
## Examples
### Discover
- python3 fuzz.py discover http://localhost/ --common-words=/words.txt
- python3 fuzz.py discover http://localhost/ --custom-auth=dvwa --common-words=/words.txt
- python3 fuzz.py discover http://localhost/ --custom-auth=dvwa --common-words=/words.txt --extensions=/extensions.txt
### Test
- python3 fuzz.py test http://localhost/ --custom-auth=dvwa --common-words=/words.txt --vectors=/vectors.txt --sensitive=/sensitive.txt
- python3 fuzz.py test http://localhost/ --custom-auth=dvwa --common-words=/words.txt --vectors=/vectors.txt --sanitized=/badchars.txt --sensitive=/sensitive.txt --slow=500