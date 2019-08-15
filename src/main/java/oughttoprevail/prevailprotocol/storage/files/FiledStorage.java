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
package oughttoprevail.prevailprotocol.storage.files;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import oughttoprevail.prevailprotocol.exception.NotEnoughBytesException;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.Storage;
import oughttoprevail.prevailprotocol.storage.fields.Field;
import oughttoprevail.prevailprotocol.storage.fields.SerDes;
import oughttoprevail.prevailprotocol.storage.files.rw.StorageFileInput;
import oughttoprevail.prevailprotocol.storage.files.rw.StorageFileOutput;
import oughttoprevail.prevailprotocol.util.Consumer;

/**
 * A file base implementation of {@link Storage}.
 */
public class FiledStorage implements Storage
{
	/**
	 * Extension for files created here
	 */
	private static final String EXTENSION = ".dat";
	/**
	 * The mode {@link RandomAccessFile} should use
	 */
	private static final String MODE = "rw";
	
	/**
	 * The {@link ExecutorService} to perform flush operations with
	 */
	private final ExecutorService flushExecutor;
	/**
	 * Settings to use
	 */
	private final Settings settings;
	/**
	 * An {@link IOException} {@link Consumer} taking exceptions when occurred
	 */
	private final Consumer<IOException> exceptionCatcher;
	/**
	 * FileChannel to be used for reading and writing
	 */
	private final FileChannel fileChannel;
	/**
	 * The file output (writer)
	 */
	private final StorageFileOutput out;
	/**
	 * The file input (reader)
	 */
	private final StorageFileInput in;
	/**
	 * List of fields in this storage
	 */
	private final List<FiledField> fields;
	/**
	 * The current flush future
	 */
	private Future<?> currentFlush;
	/**
	 * Whether this storage has been closed
	 */
	private boolean closed;
	
	/**
	 * Constructs a new {@link FiledStorage} with the specified parameters.
	 *
	 * @param path for the file
	 * @param writeByteBuffer to write with
	 * @param readByteBuffer to read with
	 * @param exceptionCatcher to take {@link IOException} exceptions
	 * @param flushExecutor to perform flush operations with
	 * @param settings to use
	 */
	public FiledStorage(String path,
						ByteBuffer writeByteBuffer,
						ByteBuffer readByteBuffer,
						Consumer<IOException> exceptionCatcher,
						ExecutorService flushExecutor,
						Settings settings)
	{
		this.exceptionCatcher = exceptionCatcher;
		this.flushExecutor = flushExecutor;
		this.settings = settings;
		try
		{
			File file = new File(path + EXTENSION);
			//make sure the file is created
			//make sure the parent file is created since you can't create the file if the parent file is missing
			File parentFile = file.getParentFile();
			if(parentFile != null)
			{
				//use mkdirs to make sure all other directories are also created
				parentFile.mkdirs();
			}
			file.createNewFile();
			//create a RandomAccessFile for it's channel, it's better to get it from RandomAccessFile instead of FileChannel.open for android support
			fileChannel = new RandomAccessFile(file, MODE).getChannel();
			
			out = new StorageFileOutput(fileChannel, writeByteBuffer, exceptionCatcher, settings);
			in = new StorageFileInput(fileChannel, readByteBuffer, exceptionCatcher, settings);
			//create a thread-safe list
			fields = new CopyOnWriteArrayList<>();
		} catch(IOException e)
		{
			exceptionCatcher.accept(e);
			throw new IllegalStateException("IOException thrown when creating FiledStorage", e);
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public <T> Field<T> getField(SerDes<T> serDes)
	{
		//try to get value from input
		T value = null;
		if(in.hasNext())
		{
			try
			{
				value = serDes.deserialize(in, settings);
			} catch(NotEnoughBytesException ignored)
			{
			}
		}
		FiledField<T> filedField = new FiledField<>(serDes, value);
		fields.add(filedField);
		return filedField;
	}
	
	/**
	 * Closes the underlying file channel if it wasn't already closed after the pending flush (if any) has finished
	 */
	void close()
	{
		//if this is already closed we shouldn't closed again
		if(closed)
		{
			return;
		}
		closed = true;
		//make sure the flush is done
		if(hasFlushNotRan())
		{
			try
			{
				currentFlush.get();
			} catch(InterruptedException ignored)
			{
				Thread.currentThread().interrupt();
			} catch(ExecutionException e)
			{
				e.printStackTrace();
			}
		}
		currentFlush = null;
		try
		{
			fileChannel.close();
		} catch(IOException e)
		{
			exceptionCatcher.accept(e);
		}
		for(FiledField<?> field : fields)
		{
			field.set(null);
		}
		fields.clear();
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void flush()
	{
		//if this storage is closed we can't flush anymore
		if(closed)
		{
			return;
		}
		//try to cancel the last flush if it's has still yet to run
		if(hasFlushNotRan())
		{
			currentFlush.cancel(false);
		}
		//submit a flush to the queue
		currentFlush = flushExecutor.submit(() ->
		{
			try
			{
				fileChannel.truncate(0);
			} catch(IOException e)
			{
				exceptionCatcher.accept(e);
				return;
			}
			for(FiledField filedField : fields)
			{
				filedField.write(out, settings);
			}
			out.flushIfRemaining();
		});
	}
	
	/**
	 * @return whether the last {@link #flush()} invocation hasn't flushed yet
	 */
	private boolean hasFlushNotRan()
	{
		return currentFlush != null && !currentFlush.isDone();
	}
}