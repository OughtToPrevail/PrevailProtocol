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
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import oughttoprevail.prevailprotocol.exception.NotMainDirectoryException;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.Directory;
import oughttoprevail.prevailprotocol.storage.Storage;
import oughttoprevail.prevailprotocol.util.Consumer;

/**
 * A file base implementation of {@link Directory}.
 */
public class FiledDirectory implements Directory
{
	/**
	 * Map of path to storage.
	 * This map helps to guarantee that we wont be loading a file twice and close file channels at bulk.
	 * To clear this map {@link #finish()} should be invoked
	 */
	private final Map<String, FiledStorage> storageMap;
	/**
	 * File path to this directory
	 */
	private final String path;
	/**
	 * Path for storage identifiers.
	 * This path starts empty from the {@link #mainDirectory} and separated with {@link File#separatorChar} for each directory & file.
	 * This is useful to not make the key in {@link #storageMap} be shorter (because the {@link #path} will contain the initial path specified in
	 * the constructor)
	 */
	private final String storagePath;
	
	//I need to use 2 buffers because writing will happen in the executor while reading will happen in this thread
	/**
	 * Writing buffer
	 */
	private final ByteBuffer writeByteBuffer;
	/**
	 * Read buffer
	 */
	private final ByteBuffer readByteBuffer;
	/**
	 * An {@link IOException} {@link Consumer} taking exceptions when occurred
	 */
	private final Consumer<IOException> exceptionCatcher;
	/**
	 * Whether this directory is the main (first) directory
	 */
	private final boolean mainDirectory;
	/**
	 * Executor to use for background tasks, this is used to increase performance
	 */
	private final ExecutorService executor;
	/**
	 * Settings to use
	 */
	private Settings settings;
	
	/**
	 * Constructs a new {@link FiledDirectory} for the specified path.
	 *
	 * @param path for this directory
	 */
	public FiledDirectory(String path, int bufferSize, Consumer<IOException> exceptionCatcher)
	{
		this(new HashMap<>(),
				path,
				"",
				ByteBuffer.allocateDirect(bufferSize),
				ByteBuffer.allocateDirect(bufferSize),
				exceptionCatcher,
				true,
				Executors.newSingleThreadExecutor(r -> new Thread(r, "Storage-Executor")),
				null);
	}
	
	/**
	 * Constructs a new {@link FiledDirectory} with the specified storageMap and specified path.
	 */
	private FiledDirectory(Map<String, FiledStorage> storageMap,
						   String path,
						   String storagePath,
						   ByteBuffer writeByteBuffer,
						   ByteBuffer readByteBuffer,
						   Consumer<IOException> exceptionCatcher,
						   boolean mainDirectory,
						   ExecutorService executor,
						   Settings settings)
	{
		this.storageMap = storageMap;
		this.path = path;
		this.storagePath = storagePath;
		this.writeByteBuffer = writeByteBuffer;
		this.readByteBuffer = readByteBuffer;
		this.exceptionCatcher = exceptionCatcher;
		this.mainDirectory = mainDirectory;
		this.executor = executor;
		this.settings = settings;
	}
	
	public void initSettings(Settings settings)
	{
		this.settings = settings;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Storage storage(String storageName)
	{
		String newStoragePath = combine(storagePath, storageName);
		FiledStorage storage;
		if((storage = storageMap.get(newStoragePath)) != null)
		{
			return storage;
		}
		storage = new FiledStorage(combine(path, storageName), writeByteBuffer, readByteBuffer, exceptionCatcher, executor, settings);
		storageMap.put(newStoragePath, storage);
		return storage;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Directory directory(String directoryName)
	{
		return new FiledDirectory(storageMap,
				combine(path, directoryName),
				combine(storagePath, directoryName),
				writeByteBuffer,
				readByteBuffer,
				exceptionCatcher,
				false,
				executor,
				settings);
	}
	
	/**
	 * @param path the path to combine with the name
	 * @param name to combine with the specified path
	 * @return if the specified path is empty ({@link String#isEmpty()}) then the specified name is returned, else the specified path combined with
	 * the specified name
	 */
	private String combine(String path, String name)
	{
		return path.isEmpty() ? name : path + File.separatorChar + name;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void delete()
	{
		//we have to delete the path in the same thread because we are possibly going to remove from the storage map
		delete(new File(path), storagePath);
	}
	
	/**
	 * Deletes the specified file and if it's a directory it invokes this method again with all the directories files.
	 * The {@link FiledStorage} of the specified file (if exists) is closed and removed.
	 *
	 * @param file to delete
	 * @param storagePath of the file to delete
	 */
	private void delete(File file, String storagePath)
	{
		File[] children = file.listFiles();
		if(children == null)
		{
			FiledStorage filedStorage = storageMap.remove(storagePath);
			if(filedStorage != null)
			{
				filedStorage.close();
			}
		} else
		{
			for(File child : children)
			{
				delete(child, combine(storagePath, child.getName()));
			}
		}
		if(!file.delete())
		{
			Throwable cause = detectReasonDeletionFailed(file);
			exceptionCatcher.accept(new IOException("Failed to delete " + file.getAbsolutePath() + "!", cause));
		}
	}
	
	/**
	 * Tries to detect the reason {@link File#delete()} failed.
	 *
	 * @param file who failed in {@link File#delete()}
	 * @return the cause {@link File#delete()} failed
	 */
	private Throwable detectReasonDeletionFailed(File file)
	{
		try
		{
			String[] list;
			if(!file.exists())
			{
				return new IOException("File doesn't exist!");
			} else if((list = file.list()) != null && list.length > 0)
			{
				return new IOException("Directory isn't empty!");
			} else if(!file.canWrite())
			{
				return new IOException("No write permission!");
			} else
			{
				return null;
			}
		} catch(SecurityException e)
		{
			return e;
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void finish() throws NotMainDirectoryException
	{
		if(!mainDirectory)
		{
			throw new NotMainDirectoryException();
		}
		//close all storages
		for(FiledStorage storage : storageMap.values())
		{
			storage.close();
		}
		storageMap.clear();
		executor.shutdown();
	}
}