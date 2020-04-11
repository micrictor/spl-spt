#!/usr/bin/env python
# coding: utf-8

# In[27]:


import pandas as pd
import matplotlib.pyplot as plt


# In[28]:


samples = ['google','shade-ransomware','trickbot']

dataframes = dict()
for sample in samples:
    with open(sample + "/spl.log") as fl:
        dataframes[sample] = pd.read_json(fl, lines=True)


# In[81]:


google_spls = []
for x in dataframes['google']['orig_spl'].iloc:
    google_spls += x

plt.subplot(1,3,1)
plt.suptitle("Sequence of packet lengths - Originator")
plt.title("Google")
plt.plot(google_spls, 'ko-')
plt.xlabel("Sequence")
plt.ylabel("Packet size")


shade_spls = []
for x in dataframes['shade-ransomware']['orig_spl'].iloc:
    shade_spls += x


plt.axis([0,len(shade_spls),0,max(google_spls)])

plt.subplot(1,3,3)
plt.title("Shade Ransomware")
plt.plot(shade_spls, 'ro-')
plt.xlabel("Sequence")
plt.ylabel("Packet size")
plt.axis([0,len(shade_spls),0,max(shade_spls)])

plt.show()


# In[83]:


google_spls = []
for x in dataframes['google']['resp_spl'].iloc:
    google_spls += x

plt.subplot(1,3,1)
plt.suptitle("Sequence of packet lengths - Responder")
plt.title("Google")
plt.plot(google_spls, 'ko-')
plt.xlabel("Sequence")
plt.ylabel("Packet size")


shade_spls = []
for x in dataframes['shade-ransomware']['resp_spl'].iloc:
    shade_spls += x


plt.axis([0,len(shade_spls),0,max(google_spls)])

plt.subplot(1,3,3)
plt.title("Shade Ransomware")
plt.plot(shade_spls, 'ro-')
plt.xlabel("Sequence")
plt.ylabel("Packet size")
plt.axis([0,len(shade_spls),0,max(shade_spls)])
plt.show()


# In[85]:


google_spts = []
for x in dataframes['google']['orig_spt'].iloc:
    google_spts += x

plt.subplot(1,3,1)
plt.suptitle("Sequence of packet times - Originator")
plt.title("Google")
plt.plot(google_spts, 'ko-')
plt.xlabel("Sequence")
plt.ylabel("Packet size")


shade_spts = []
for x in dataframes['shade-ransomware']['orig_spt'].iloc:
    shade_spts += x


plt.axis([0,len(shade_spts),0,max(google_spts)])

plt.subplot(1,3,3)
plt.title("Shade Ransomware")
plt.plot(shade_spts, 'ro-')
plt.xlabel("Sequence")
plt.ylabel("Packet size")
plt.axis([0,len(shade_spts),0,max(shade_spts)])
plt.show()


# In[86]:


google_spts = []
for x in dataframes['google']['resp_spt'].iloc:
    google_spts += x

plt.subplot(1,3,1)
plt.suptitle("Sequence of packet times - Responder")
plt.title("Google")
plt.plot(google_spts, 'ko-')
plt.xlabel("Sequence")
plt.ylabel("Packet size")


shade_spts = []
for x in dataframes['shade-ransomware']['resp_spt'].iloc:
    shade_spts += x


plt.axis([0,len(shade_spts),0,max(google_spts)])

plt.subplot(1,3,3)
plt.title("Shade Ransomware")
plt.plot(shade_spts, 'ro-')
plt.xlabel("Sequence")
plt.ylabel("Packet size")
plt.axis([0,len(shade_spts),0,max(shade_spts)])
plt.show()


# In[ ]:




