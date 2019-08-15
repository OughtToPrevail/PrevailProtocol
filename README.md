# PrevailProtocol
The PrevailProtocol is a easy-to-use library which implements a modified version of the Signal Protocol.

Note: I decided to use the name PrevailProtocol because I cannot choose a name with "Signal Protocol" in it since it's 
trademarked.

## Features
* Cross platform (PC and Android)
* Fast and efficient
* Everything has documentation
* Based on a modified version of [Signal's documentation](https://signal.org/docs/)
* Supports header encryption
* Supports changes of properties with a single line of code

## Maven
TODO

## Purpose
The purpose of the PrevailProtocol was mostly so I could learn cryptography better and I thought Signal Protocol looked
great, but to ensure I understood everything there and I saw their 
[implementation](https://github.com/signalapp/libsignal-protocol-java) was very messy (my opinion) I decided to make it 
into a project.

Note: Now that I understand it I most likely will not be uploading any updates to this project.

# Examples
Examples can found in the test directory.

Note: when using examples, if there are different settings between them the application directory needs to be removed.
By default the application directory can be found at user.home with the name "PrevailProtocolData".

# Credits
This library uses [curve25519-java](https://github.com/signalapp/curve25519-java) and based on 
[Signal documentation](https://signal.org/docs/).

Also thanks to [5_c_d](https://community.signalusers.org/u/5_c_d/) which helped when I ran into problems.

## License
This program is released under GPLv3

## Documentation
Most classes are more or less documented, often if you see a method is a getter/setter or a constructor takes a
parameter and it's not documented it probably means the field is documented.

## How to use PrevailProtocol (User in depth)
A user manages all features of the library in one class.

### How to create a user
To create a user you must first have a user identifier, this could be provided by a user, randomly generated or whatever 
you can think of, as long as it's unique.

Once you have the user identifier just initiate one of it's 2 constructors.
#### First constructor
The first constructor is basically just creating a User with your identifier and the default settings.
```java
User user = new User(yourUserIdentifier);
```
#### Second constructor
The second constructor creates a User with your identifier and the specified settings
```java
User user = new User(yourUserIdentifier, yourSettings);
```

### Before you can use a User
Before you can start using a User you must first send it's public data bundle values to the server, to do so, get the data bundle then
remove it, once it's removed the User is ready for registering sessions

### How to register sessions
To register sessions invoke <which type of user are you in the session (alice/bob)>Register (examples: aliceRegister or 
bobRegister), sessions can also be created by decrypting messages using Messenger.

## Messenger in depth
The Messenger class is in charge of encrypting and decrypting messages.

### How to get
To get a Messenger you can use Session.getMessenger() or use User.getMessenger(userId, deviceId).
User.getMessenger(...) is the recommended approach since it allows you to use a Messenger without a session
tho this Messenger will not be able to encrypt until a message with  a registerMessage is decrypted.

### Encryption
Encrypting messages using Messenger is not recommended but possible, a better way is to use User.encryptMessage(...) which adds more functionality.

A Messenger can only encrypt a byte[].

### Decryption
Messenger decryption has many more options.

#### Decrypting with byte[]
Decrypting with a byte[] is good for testing but in a real application you most likely wont be able to get the byte[]
without including an integer of the length of the message which is not required, for these reasons there are other
decryption functions.

#### Decrypting with Reader
Decrypting with Reader is a very simple approach, you create a class which implements a Reader and the Messenger
use it to read the required values.
This approach is easy and recommended for blocking reader approaches

#### Decrypting with ConsumerReader
If your application cannot read blocking decrypting with ConsumerReader is for you, this approach will read all the
required values using consumers.

#### Decrypting with all the values
If you have somehow already have the values you can use decryptMessage or decryptWithEncryptedHeader which would
decrypt using the given values.

## Settings in depth
The settings class allows to change almost all properties of the protocol very easily.

This is good for projects who want to use newer/older algorithms, different identifiers and different features.

### How to change property
```java
Settings settings = Settings.create().propertyName(value);
```
where propertyName is the property name (example: signedPreKeyKeepAlive) and value is the value for the property
(example: 1 day)

Example:
```java
Settings settings = Settings.create().signedPreKeyKeepAlive(TimeUnit.DAYS.toMillis(1));
```

## UID in depth
A UID is an identifier for users, devices, keys etc...

A UID is generated using a UIDFactory, a UIDFactory will also serialize and deserialize a UID to
to be storage compatible.

UID and UIDFactory so anyone is welcome to modify them (then set in the settings the
uidFactory or/and userIdFactory properties).

There are multiple times of already implemented UIDs, TimedUID, StringUID and UUIDWrapper, each also has his own factory.

### TimedUID
A timed UID is a always unique UID which is based on a time and counter.

### StringWrapper
A string UID is good for user identifiers (phone numbers, nicknames, etc...) but really not
recommended for anything else as it's factory generateUID is an unsupported operation so it can only be used as a
userIdFactory.

### UUIDWrapper
UUIDWrapper is not recommended for anything but if you're already using UUID and can't change it, 
UUIDWrapper is the class for you.

## AsymmetricCryptography in depth
AsymmetricCryptography is a class responsible for generating key pairs, performing key exchanges, signing and verifying.

This of course makes AsymmetricCryptography one of the more important classes so if you are planning on changing the 
AsymmetricCryptography think long and hard on your decision.

An example of a possible use is to change to Ed448 encase you want stronger yet slower encryption.

## Data storage in depth
Data storage is very simple and is based on 2 interfaces, Directory and Storage.

### Directory
Directory is in charge of creating storages, directory names might be different but storage names may match
between directories so directories are there to ensure paths remain unique.

### Storage
Storage is in charge of actually storing values, values are represented as Fields, fields are always created in
order so there is no need for an identifier (key) for each value, this creates efficient storage.

### Implemented types
There is FiledDirectory and FiledStorage which are used by default and store fields in files.
There is also InMemoryDirectory and InMemoryStorage which is recommended for applications who wish to not
store any data for future uses.

## Group in depth
Group is the class which manages a group.

You can create a group using a User class.

### How to use
Groups are very simple, all you need is to notify them when a member joins (and provide a sender key with it) and when a
member leaves, everything else such as encryption and decryption, getting a collection of members etc... is 
provided in the class for easy use.

#### How to join
To join a Group you must send your sender key to the whole group, a method to encrypt sender keys is provided.
The sender key should be transmitted using pairwise encryption (Messenger class) and then decrypted, once decrypted
it should be provided in the member join method.

#### How to leave
Leaving is quite simple but has a disadvantage, you just provide the user and device identifiers of the member who left.
Then an encrypted key array is returned, this is the sender key for the new collection of members in the groups, this part
is necessary so an old member cannot decrypt new messages.

Leaving also has a disadvantage: if a message is sent before the member left but arrived after the message cannot be 
decrypted anymore.

This is because once a member has left it's sender keys are deleted, if they were kept, a member could continue sending
messages after he left and they would be successfully decrypted.