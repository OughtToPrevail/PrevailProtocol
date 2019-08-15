/*
PrevailProtocol.
Copyright (C) 2019  https://github.com/OughtToPrevail

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package oughttoprevail.prevailprotocol.storage;

import java.security.MessageDigest;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeUnit;

import oughttoprevail.prevailprotocol.exception.CounterTooLargeException;
import oughttoprevail.prevailprotocol.keys.SkippedKey;
import oughttoprevail.prevailprotocol.messenger.MessageKeys;
import oughttoprevail.prevailprotocol.settings.Settings;

/**
 * Skipped keys storage manager, stores, retrieves and removes when appropriate skipped keys.
 */
public class SkippedKeysStorage
{
	/**
	 * Skipped keys storage name
	 */
	private static final String SKIPPED_KEYS_STORAGE = "SkippedKeys";
	
	/**
	 * Storage in which the skipped keys are stored
	 */
	private final Storage storage;
	/**
	 * Settings to use
	 */
	private final Settings settings;
	/**
	 * List of stored skipped keys
	 */
	private final List<SkippedKey> skippedKeys;
	/**
	 * Lock for changing the {@link #skippedKeys}
	 */
	private final Object lock = new Object();
	
	/**
	 * Constructs a new {@link SkippedKeysStorage}.
	 *
	 * @param directory to create skipped keys storage in
	 * @param settings to use
	 */
	public SkippedKeysStorage(Directory directory, Settings settings)
	{
		storage = directory.storage(SKIPPED_KEYS_STORAGE);
		this.settings = settings;
		this.skippedKeys = storage.getFieldList(SkippedKey.SER_DES);
		//load and schedule
		synchronized(lock)
		{
			for(SkippedKey storedMessageKeys : skippedKeys)
			{
				putAndSchedule(storedMessageKeys, storedMessageKeys.getExpirationTime() - System.currentTimeMillis());
			}
		}
	}
	
	/**
	 * @param skippedKeysStorage who will skip the keys or {@code null} if there isn't one
	 * @param myCounter is my current counter
	 * @param receivedCounter is the counter received from the recipient
	 * @param settings to use
	 * @return {@code true} if there isn't actually a need to skip, else {@code false}
	 * @throws CounterTooLargeException either if there was a need for skip but the specified skippedKeysStorage is {@code null} or if the skipping
	 * the amount of keys required passes {@link Settings#getMaxSkipKeys()}
	 */
	public static boolean ensureCanSkip(SkippedKeysStorage skippedKeysStorage, int myCounter, int receivedCounter, Settings settings)
			throws CounterTooLargeException
	{
		int mustSkip = receivedCounter - myCounter;
		//if we don't have anything to skip we can return
		if(mustSkip == 0)
		{
			return true;
		}
		//if we need to skip but skippedKeyStorage doesn't exist then we must throw an exception
		if(skippedKeysStorage == null)
		{
			throw new CounterTooLargeException(String.format("Received counter (%s) is bigger than current counter (%s) and skippedKeys is off!",
					receivedCounter,
					myCounter));
		}
		int maxSkipKeys = settings.getMaxSkipKeys();
		//if we need to skip more than the allowed keys to skip then we must throw an exception
		if(mustSkip > maxSkipKeys)
		{
			throw new CounterTooLargeException(String.format("Received counter is too large, must skip over %d to skip keys while maxSkipKeys is %d.",
					mustSkip,
					maxSkipKeys));
		}
		return false;
	}
	
	/**
	 * Adds the specified messageKeys with the specified key and counter as their identifiers.
	 *
	 * @param key identifier of the message keys
	 * @param authKey optional extra authentication key to access when using {@link #getSkippedKeys()}
	 * @param counter identifier of message keys
	 * @param messageKeys to store
	 */
	public void addSkippedKey(byte[] key, byte[] authKey, int counter, MessageKeys messageKeys)
	{
		long skippedKeyKeepAlive = settings.getSkippedKeyKeepAlive();
		synchronized(lock)
		{
			SkippedKey skippedKey = new SkippedKey(counter,
					key,
					authKey,
					System.currentTimeMillis() + settings.getSkippedKeyKeepAlive(),
					messageKeys);
			if(skippedKeys.size() >= settings.getMaxStoredSkippedKeys())
			{
				skippedKeys.remove(0);
			}
			skippedKeys.add(skippedKey);
			storage.flush();
			putAndSchedule(skippedKey, skippedKeyKeepAlive);
		}
	}
	
	/**
	 * @param key identifier of the message keys
	 * @param counter identifier of the message keys
	 * @return the message keys which have the identifiers of the specified key and counter are returned
	 */
	public MessageKeys getSkippedMessageKeys(byte[] key, int counter)
	{
		Iterator<SkippedKey> iterator = skippedKeys.iterator();
		while(iterator.hasNext())
		{
			SkippedKey skippedKey = iterator.next();
			if(skippedKey.getCounter() == counter && MessageDigest.isEqual(key, skippedKey.getKey()))
			{
				iterator.remove();
				storage.flush();
				return skippedKey.cancelThenGetMessageKeys();
			}
		}
		return null;
	}
	
	/**
	 * Flush all changes to storage
	 */
	public void flush()
	{
		storage.flush();
	}
	
	/**
	 * @return the list of skipped keys
	 */
	public List<SkippedKey> getSkippedKeys()
	{
		return skippedKeys;
	}
	
	/**
	 * @return lock for changes in the skipped keys list
	 */
	public Object getLock()
	{
		return lock;
	}
	
	/**
	 * If a map exists, then the specified skippedKey is put, then it schedules a removal of the skipped key in the specified time.
	 *
	 * @param skippedKey to put in the map then schedule a removal for
	 * @param time is in how much time to remove the skipped key
	 */
	private void putAndSchedule(SkippedKey skippedKey, long time)
	{
		skippedKey.setFuture(settings.getScheduler().schedule(() ->
		{
			synchronized(lock)
			{
				this.skippedKeys.remove(skippedKey);
			}
			storage.flush();
		}, time, TimeUnit.MILLISECONDS));
	}
}