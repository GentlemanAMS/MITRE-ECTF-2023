# Host Tools :computer::hammer_and_wrench:
Host tools are used to interact with the car and fob devices to utilize their functionalities. The host tools are written in Python 3. There are 4 host tools:

* [enable_tool](enable_tool): Implements sending a packaged feature to a fob
* [package_tool](package_tool): Implements creating a packaged feature
* [unlock_tool](unlock_tool): Listens for unlock messages from the car while unlocking via button
* [pair_tool](pair_tool): Implements pairing an unpaired fob through a paired fob

## Helper Script

* [message.py](message.py): Implements methods for sending, receiving and printing messages between the host and the car/fob.