/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.nifi.processors.smb;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2CreateOptions;
import com.hierynomus.mssmb2.SMBApiException;
import org.apache.nifi.annotation.behavior.InputRequirement;
import org.apache.nifi.annotation.behavior.InputRequirement.Requirement;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.annotation.behavior.ReadsAttribute;
import org.apache.nifi.annotation.behavior.ReadsAttributes;
import org.apache.nifi.annotation.lifecycle.OnScheduled;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.SeeAlso;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.flowfile.attributes.CoreAttributes;
import org.apache.nifi.processor.*;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.util.StandardValidators;
import org.apache.nifi.expression.ExpressionLanguageScope;
import org.apache.nifi.logging.ComponentLog;

import java.io.FileFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.smbj.share.File;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

@Tags({"samba, smb, cifs, files, get"})
@CapabilityDescription("Writes the contents of a FlowFile to a samba network location. " +
    "Use this processor instead of a cifs mounts if share access control is important.")
@SeeAlso({})
@ReadsAttributes({@ReadsAttribute(attribute="filename", description="The filename to use when writing the FlowFile to the network folder.")})
public class GetSmbFile extends AbstractProcessor {
    public static final String SHARE_ACCESS_NONE = "none";
    public static final String SHARE_ACCESS_READ = "read";
    public static final String SHARE_ACCESS_READDELETE = "read, delete";
    public static final String SHARE_ACCESS_READWRITEDELETE = "read, write, delete";


    public static final PropertyDescriptor HOSTNAME = new PropertyDescriptor.Builder()
            .name("Hostname")
            .description("The network host to which files should be written.")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    public static final PropertyDescriptor SHARE = new PropertyDescriptor.Builder()
            .name("Share")
            .description("The network share to which files should be written.")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    public static final PropertyDescriptor DIRECTORY = new PropertyDescriptor.Builder()
            .name("Directory")
            .description("The network folder to which files should be written. You may use expression language.")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    public static final PropertyDescriptor DOMAIN = new PropertyDescriptor.Builder()
            .name("Domain")
            .description("The domain use for authentication")
            .required(false)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    public static final PropertyDescriptor USERNAME = new PropertyDescriptor.Builder()
            .name("Username")
            .description("The username use for authentication")
            .required(false)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    public static final PropertyDescriptor PASSWORD = new PropertyDescriptor.Builder()
            .name("Password")
            .description("The password use for authentication")
            .required(false)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .sensitive(true)
            .build();

    public static final PropertyDescriptor SHARE_ACCESS = new PropertyDescriptor.Builder()
            .name("Share Access Strategy")
            .description("Indicates which shared access are granted on the file during the write. " +
                "None is the most restrictive, but the safest setting to prevent corruption.")
            .required(true)
            .defaultValue(SHARE_ACCESS_NONE)
            .allowableValues(SHARE_ACCESS_NONE, SHARE_ACCESS_READ, SHARE_ACCESS_READDELETE, SHARE_ACCESS_READWRITEDELETE)
            .build();
    public static final PropertyDescriptor RECURSE = new PropertyDescriptor.Builder()
            .name("Recurse Subdirectories")
            .description("Indicates whether or not to pull files from subdirectories")
            .required(true)
            .allowableValues("true", "false")
            .defaultValue("true")
            .build();
    public static final PropertyDescriptor KEEP_SOURCE_FILE = new PropertyDescriptor.Builder()
            .name("Keep Source File")
            .description("If true, the file is not deleted after it has been copied to the Content Repository; "
                    + "this causes the file to be picked up continually and is useful for testing purposes.  "
                    + "If not keeping original NiFi will need write permissions on the directory it is pulling "
                    + "from otherwise it will ignore the file.")
            .required(true)
            .allowableValues("true", "false")
            .defaultValue("false")
            .build();
    public static final PropertyDescriptor FILE_FILTER = new PropertyDescriptor.Builder()
            .name("File Filter")
            .description("Only files whose names match the given regular expression will be picked up")
            .required(true)
            .defaultValue("[^\\.].*")
            .addValidator(StandardValidators.REGULAR_EXPRESSION_VALIDATOR)
            .build();
    public static final PropertyDescriptor PATH_FILTER = new PropertyDescriptor.Builder()
            .name("Path Filter")
            .description("When " + RECURSE.getName() + " is true, then only subdirectories whose path matches the given regular expression will be scanned")
            .required(false)
            .addValidator(StandardValidators.REGULAR_EXPRESSION_VALIDATOR)
            .build();
    public static final PropertyDescriptor MIN_AGE = new PropertyDescriptor.Builder()
            .name("Minimum File Age")
            .description("The minimum age that a file must be in order to be pulled; any file younger than this amount of time (according to last modification date) will be ignored")
            .required(true)
            .addValidator(StandardValidators.TIME_PERIOD_VALIDATOR)
            .defaultValue("0 sec")
            .build();
    public static final PropertyDescriptor MAX_AGE = new PropertyDescriptor.Builder()
            .name("Maximum File Age")
            .description("The maximum age that a file must be in order to be pulled; any file older than this amount of time (according to last modification date) will be ignored")
            .required(false)
            .addValidator(StandardValidators.createTimePeriodValidator(100, TimeUnit.MILLISECONDS, Long.MAX_VALUE, TimeUnit.NANOSECONDS))
            .build();
    public static final PropertyDescriptor MIN_SIZE = new PropertyDescriptor.Builder()
            .name("Minimum File Size")
            .description("The minimum size that a file must be in order to be pulled")
            .required(true)
            .addValidator(StandardValidators.DATA_SIZE_VALIDATOR)
            .defaultValue("0 B")
            .build();
    public static final PropertyDescriptor MAX_SIZE = new PropertyDescriptor.Builder()
            .name("Maximum File Size")
            .description("The maximum size that a file can be in order to be pulled")
            .required(false)
            .addValidator(StandardValidators.DATA_SIZE_VALIDATOR)
            .build();
    public static final PropertyDescriptor IGNORE_HIDDEN_FILES = new PropertyDescriptor.Builder()
            .name("Ignore Hidden Files")
            .description("Indicates whether or not hidden files should be ignored")
            .allowableValues("true", "false")
            .defaultValue("true")
            .required(true)
            .build();
    public static final PropertyDescriptor POLLING_INTERVAL = new PropertyDescriptor.Builder()
            .name("Polling Interval")
            .description("Indicates how long to wait before performing a directory listing")
            .required(true)
            .addValidator(StandardValidators.TIME_PERIOD_VALIDATOR)
            .defaultValue("0 sec")
            .build();
    public static final PropertyDescriptor BATCH_SIZE = new PropertyDescriptor.Builder()
            .name("Batch Size")
            .description("The maximum number of files to pull in each iteration")
            .required(true)
            .addValidator(StandardValidators.POSITIVE_INTEGER_VALIDATOR)
            .defaultValue("10")
            .build();

    public static final String FILE_CREATION_TIME_ATTRIBUTE = "file.creationTime";
    public static final String FILE_LAST_MODIFY_TIME_ATTRIBUTE = "file.lastModifiedTime";
    public static final String FILE_LAST_ACCESS_TIME_ATTRIBUTE = "file.lastAccessTime";
    public static final String FILE_OWNER_ATTRIBUTE = "file.owner";
    public static final String FILE_GROUP_ATTRIBUTE = "file.group";
    public static final String FILE_PERMISSIONS_ATTRIBUTE = "file.permissions";
    public static final String FILE_MODIFY_DATE_ATTR_FORMAT = "yyyy-MM-dd'T'HH:mm:ssZ";

    public static final Relationship REL_SUCCESS = new Relationship.Builder().name("success").description("All files are routed to success").build();

    private List<PropertyDescriptor> descriptors;
    private Set<Relationship> relationships;


    private final BlockingQueue<String> fileQueue = new LinkedBlockingQueue<>();
    private final Set<String> inProcess = new HashSet<>();    // guarded by queueLock
    private final Set<String> recentlyProcessed = new HashSet<>();    // guarded by queueLock
    private final Lock queueLock = new ReentrantLock();

    private final Lock listingLock = new ReentrantLock();

    private final AtomicLong queueLastUpdated = new AtomicLong(0L);

    private SMBClient smbClient = null;

    @Override
    protected void init(final ProcessorInitializationContext context) {
        final List<PropertyDescriptor> descriptors = new ArrayList<PropertyDescriptor>();
        descriptors.add(HOSTNAME);
        descriptors.add(SHARE);
        descriptors.add(DIRECTORY);
        descriptors.add(DOMAIN);
        descriptors.add(USERNAME);
        descriptors.add(PASSWORD);
        descriptors.add(SHARE_ACCESS);
        descriptors.add(DIRECTORY);
        descriptors.add(FILE_FILTER);
        descriptors.add(PATH_FILTER);
        descriptors.add(BATCH_SIZE);
        descriptors.add(KEEP_SOURCE_FILE);
        descriptors.add(RECURSE);
        descriptors.add(POLLING_INTERVAL);
        descriptors.add(IGNORE_HIDDEN_FILES);
        descriptors.add(MIN_AGE);
        descriptors.add(MAX_AGE);
        descriptors.add(MIN_SIZE);
        descriptors.add(MAX_SIZE);
        this.descriptors = Collections.unmodifiableList(descriptors);

        final Set<Relationship> relationships = new HashSet<Relationship>();
        relationships.add(REL_SUCCESS);
        this.relationships = Collections.unmodifiableSet(relationships);

        if (this.smbClient == null) {
            initSmbClient();
        }
    }

    @Override
    public Set<Relationship> getRelationships() {
        return this.relationships;
    }

    @Override
    public final List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return descriptors;
    }

    @OnScheduled
    public void onScheduled(final ProcessContext context) {
        fileQueue.clear();
    }

    public void initSmbClient() {
        initSmbClient(new SMBClient());
    }

    public void initSmbClient(SMBClient smbClient) {
        this.smbClient = smbClient;
    }

    private Set<String> performListing(final DiskShare diskShare, final String directory, final String filter, final boolean recurseSubdirectories) {
        final Set<String> queue = new HashSet<>();
        if (!diskShare.folderExists(directory)) {
            return queue;
        }

        final List<FileIdBothDirectoryInformation> children = diskShare.list(directory);
        if (children == null) {
            return queue;
        }

        for (final FileIdBothDirectoryInformation child : children) {
            final String filename = child.getFileName();
            if (filename.equals(".") || filename.equals("..")) {
                continue;
            }
            final String fullPath = directory + "\\" + filename;
            if ((child.getFileAttributes() & FileAttributes.FILE_ATTRIBUTE_DIRECTORY.getValue()) != 0) {
                if (recurseSubdirectories) {
                    queue.addAll(performListing(diskShare, fullPath, filter, true));
                }
            } else {
                queue.add(fullPath);
            }
        }

        return queue;
    }

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {

        final ComponentLog logger = getLogger();

        final String hostname = context.getProperty(HOSTNAME).getValue();
        final String shareName = context.getProperty(SHARE).getValue();

        final String domain = context.getProperty(DOMAIN).getValue();
        final String username = context.getProperty(USERNAME).getValue();
        String password = context.getProperty(PASSWORD).getValue();

        AuthenticationContext ac = null;
        if (username != null) {
            if (password == null) {
                password = "";
            }
            ac = new AuthenticationContext(
                username,
                password.toCharArray(),
                domain);
        } else {
            ac = AuthenticationContext.anonymous();
        }


        // share access handling
        Set<SMB2ShareAccess> sharedAccess = Collections.<SMB2ShareAccess>emptySet();
        switch (context.getProperty(SHARE_ACCESS).getValue()) {
            case SHARE_ACCESS_NONE:
                /* nothing, already initiated as empty */
                break;
            case SHARE_ACCESS_READ:
                sharedAccess = EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ);
                break;
            case SHARE_ACCESS_READDELETE:
                sharedAccess = EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ, SMB2ShareAccess.FILE_SHARE_DELETE);
                break;
            case SHARE_ACCESS_READWRITEDELETE:
                sharedAccess = EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ, SMB2ShareAccess.FILE_SHARE_WRITE, SMB2ShareAccess.FILE_SHARE_DELETE);
                break;
        }

        try (Connection connection = smbClient.connect(hostname);
            Session smbSession = connection.authenticate(ac);
            DiskShare share = (DiskShare) smbSession.connectShare(shareName);) {
                final String directory = context.getProperty(DIRECTORY).getValue();
                final boolean keepingSourceFile = context.getProperty(KEEP_SOURCE_FILE).asBoolean();
                final String filter = context.getProperty(FILE_FILTER).getValue();

                if (fileQueue.size() < 100) {
                    final long pollingMillis = context.getProperty(POLLING_INTERVAL).asTimePeriod(TimeUnit.MILLISECONDS);
                    if ((queueLastUpdated.get() < System.currentTimeMillis() - pollingMillis) && listingLock.tryLock()) {
                        try {
                            final Set<String> listing = performListing(share, directory, filter, context.getProperty(RECURSE).asBoolean().booleanValue());

                            queueLock.lock();
                            try {
                                listing.removeAll(inProcess);
                                if (!keepingSourceFile) {
                                    listing.removeAll(recentlyProcessed);
                                }

                                fileQueue.clear();
                                fileQueue.addAll(listing);

                                queueLastUpdated.set(System.currentTimeMillis());
                                recentlyProcessed.clear();

                                if (listing.isEmpty()) {
                                    context.yield();
                                }
                            } finally {
                                queueLock.unlock();
                            }
                        } finally {
                            listingLock.unlock();
                        }
                    }
                }

                final int batchSize = context.getProperty(BATCH_SIZE).asInteger();
                final List<String> files = new ArrayList<>(batchSize);
                queueLock.lock();
                try {
                    fileQueue.drainTo(files, batchSize);
                    if (files.isEmpty()) {
                        return;
                    } else {
                        inProcess.addAll(files);
                    }
                } finally {
                    queueLock.unlock();
                }

                final ListIterator<String> itr = files.listIterator();
                FlowFile flowFile = null;

                try {
                    while (itr.hasNext()) {
                        final String file = itr.next();
                        final String[] fileSplits = file.split("\\\\");
                        final String filename = fileSplits[fileSplits.length - 1];

                        flowFile = session.create();
                        final long importStart = System.nanoTime();

                        try (File f = share.openFile(
                                file,
                                EnumSet.of(AccessMask.GENERIC_READ),
                                EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                                sharedAccess,
                                SMB2CreateDisposition.FILE_OPEN,
                             EnumSet.of(SMB2CreateOptions.FILE_SEQUENTIAL_ONLY));
                             InputStream is = f.getInputStream()) {

                            flowFile = session.importFrom(is, flowFile);

                            final long importNanos = System.nanoTime() - importStart;
                            final long importMillis = TimeUnit.MILLISECONDS.convert(importNanos, TimeUnit.NANOSECONDS);

                            flowFile = session.putAttribute(flowFile, CoreAttributes.FILENAME.key(), filename);
                            session.getProvenanceReporter().receive(flowFile, file, importMillis);

                            session.transfer(flowFile, REL_SUCCESS);
                            logger.info("added {} to flow", new Object[]{flowFile});

                            if (!keepingSourceFile) {
                                share.deleteOnClose(f.getFileId());
                            }

                        } catch (SMBApiException e) {
                            // do not fail whole batch if a single file cannot be accessed
                            if (e.getStatus() == NtStatus.STATUS_SHARING_VIOLATION) {
                                logger.info("Could not acquire sharing access for file {}", new Object[]{file});
                                if (flowFile != null) {
                                    session.remove(flowFile);
                                }
                                continue;
                            } else {
                                throw e;
                            }
                        } catch (Exception e) {
                            throw e;
                        }

                        if (!isScheduled()) {  // if processor stopped, put the rest of the files back on the queue.
                            queueLock.lock();
                            try {
                                while (itr.hasNext()) {
                                    final String nextFile = itr.next();
                                    fileQueue.add(nextFile);
                                    inProcess.remove(nextFile);
                                }
                            } finally {
                                queueLock.unlock();
                            }
                        }
                    }
                    session.commit();
                } catch (final Exception e) {
                    logger.error("Failed to retrieve files due to {}", e);

                    // anything that we've not already processed needs to be put back on the queue
                    if (flowFile != null) {
                        session.remove(flowFile);
                    }
                } finally {
                    queueLock.lock();
                    try {
                        inProcess.removeAll(files);
                        recentlyProcessed.addAll(files);
                    } finally {
                        queueLock.unlock();
                    }
                }
        } catch (Exception e) {
            logger.error("Could not establish smb connection because of error {}", new Object[]{e});
            context.yield();
        }
    }
}
