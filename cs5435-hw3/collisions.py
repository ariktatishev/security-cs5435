import siphash

def callhash(hashkey, inval):
    return siphash.SipHash_2_4(hashkey, inval).hash()


def ht_hash(hashkey, inval, htsize):
    return callhash(hashkey, inval) % htsize

#Put your collision-finding code here.
#Your function should output the colliding strings in a list.
def find_collisions(key, n_coll):
    s = 2 ** 16
    hashtable = [None] * s

    i = 0
    while True:
        i_str = str(i)
        hashed_str = ht_hash(key, i_str.encode(), s)
        if hashtable[hashed_str] is None:
            hashtable[hashed_str] = [i_str]
        else:
            hashtable[hashed_str].append(i_str)
        if len(hashtable[hashed_str]) == n_coll:
            return hashtable[hashed_str]
        i += 1

#Implement this function, which takes the list of
#collisions and verifies they all have the same
#SipHash output under the given key.
def check_collisions(key, colls):
    s = 2 ** 16
    check = ht_hash(key, colls[0].encode(), s)
    for coll in colls:
        hashed_str = ht_hash(key, coll.encode(), s)
        if hashed_str != check:
            return False
    return True

if __name__=='__main__':
    #Look in the source code of the app to
    #find the key used for hashing.
    # key = None
    key = b'\x00'*16
    colls = find_collisions(key, 20)
    if check_collisions(key, colls):
        print(colls)
