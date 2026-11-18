import unittest,numpy as np
from modules.crypto import digest,link,GENESIS,keypair,sign,verify
class Tests(unittest.TestCase):
 def test_sha256_deterministic(self):
  x=np.zeros((5,5,3),dtype=np.uint8); self.assertEqual(digest(x),digest(x.copy()))
 def test_pixel_change(self):
  x=np.zeros((5,5,3),dtype=np.uint8); y=x.copy(); y[0,0,0]=1; self.assertNotEqual(digest(x),digest(y))
 def test_chain_sequence(self): self.assertNotEqual(link(GENESIS,1,'a',1),link(GENESIS,2,'a',1))
 def test_ed25519(self):
  private,public=keypair(); sig=sign(private,'nonce'); self.assertTrue(verify(public,'nonce',sig)); self.assertFalse(verify(public,'other',sig))
if __name__=='__main__': unittest.main()
