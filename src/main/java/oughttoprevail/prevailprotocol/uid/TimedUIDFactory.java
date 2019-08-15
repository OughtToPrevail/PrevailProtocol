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
package oughttoprevail.prevailprotocol.uid;

import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.fields.FieldInputStream;
import oughttoprevail.prevailprotocol.storage.fields.FieldOutputStream;

/**
 * A {@link TimedUID} implementation of the {@link UIDFactory}.
 */
public class TimedUIDFactory implements UIDFactory
{
	/**
	 * A record of a time stamp which has yet to reach it's max counter
	 */
	private long timestamp = System.currentTimeMillis();
	/**
	 * A counter for the {@link TimedUID} this counter is unique for the timestamp, if it reaches {@link Short#MAX_VALUE} the timestamp changes
	 */
	private short counter = Short.MIN_VALUE;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public UID generateUID()
	{
		//if the counter has reached its max we must change the timestamp
		if(counter == Short.MAX_VALUE)
		{
			//get current time
			long now = System.currentTimeMillis();
			//if the time equals the saved timestamp we need to wait for the millisecond to end
			//create a do while loop to ensure the time changes
			while(now == timestamp)
			{
				try
				{
					//first try to wait out the millisecond by sleeping
					Thread.sleep(1);
				} catch(InterruptedException e)
				{
					//if sleeping fails try to wait it using a while loop
					while((now = System.currentTimeMillis()) == timestamp)
					{
					}
					//interrupt the thread
					Thread.currentThread().interrupt();
					//break the thread, we finished
					break;
				}
				now = System.currentTimeMillis();
			}
			//reset the counter and set the timestamp to the new timestamp
			counter = Short.MIN_VALUE;
			timestamp = now;
		}
		//create a new uid after incrementing the counter
		return new TimedUID(timestamp, counter++);
	}
	
	@Override
	public void serialize(UID uid, FieldOutputStream out, Settings settings)
	{
		TimedUID timedUID = (TimedUID) uid;
		out.writeLong(timedUID.getTime());
		out.writeShort(timedUID.getCounter());
	}
	
	@Override
	public UID deserialize(FieldInputStream in, Settings settings)
	{
		long time = in.readLong();
		short counter = in.readShort();
		return new TimedUID(time, counter);
	}
}