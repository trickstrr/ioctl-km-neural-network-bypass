# Payson IOCTL v2

This is my v2 IOCTL cheat driver. This is updated to have latest cr3 for EAC and draws way less detections than the old verison.
There is no write process memory as that draws detections but you can add it.

# MUST HAVE THE WDK AND COMPATIBLE SDK VERSION INSTALLED TO BUILD WITHOUT ERRORS!

# TrickSTRR IOCTL NeuralNetwork Bypass

This is my Kernelmode IOCTL Driver (based on Paysons IOCTL v2) that actually avoid detections with a custom made NeuralNetwork. 
It will communicate with a Server (included) that will process the logics and communicate with each client (the Server is a C2 server based on Python. An Installer-Script is included)

The Server receives the data, collected by the Client and sending Commands to each client based on the data collected by all running clients. 
currently it is only working for EAC (need more EAC driver hooks )

no pretrained nn-model is included.
A custom Debugger is included on the server and the client.

The Neural-Network is changing its own code to avoid detection. it is also intercepting some EAC functions. 
each failure and each success will improve the logic of the Neural-Network. 

still need some bug fixes that causes some BSODs. (this is not a ready2use Src. just a PoC)

it will check each change previously to avoid system crashes. 


ToDo:
- Implement more EAC hooks
- pre-training for the NN
- fix some bugs




# Credits

Based on [Payson](https://github.com/paysonism)
Made by [TrickSTRR](https://github.com/trickstrr)
