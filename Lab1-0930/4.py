from itertools import combinations, permutations
from time import time
from hashlib import sha1


select = '+*=(%245680qQwWIiNn'

for i in permutations(select, 8):
    if sha1(''.join(i).encode()).hexdigest()=='67ae1a64661ac8b4494666f58c4822408dd0a3e4':
        print(''.join(i))
        exit(0)
