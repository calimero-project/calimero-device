/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2011, 2023 B. Malinowsky

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    Linking this library statically or dynamically with other modules is
    making a combined work based on this library. Thus, the terms and
    conditions of the GNU General Public License cover the whole
    combination.

    As a special exception, the copyright holders of this library give you
    permission to link this library with independent modules to produce an
    executable, regardless of the license terms of these independent
    modules, and to copy and distribute the resulting executable under terms
    of your choice, provided that you also meet, for each linked independent
    module, the terms and conditions of the license of that module. An
    independent module is a module which is not derived from or based on
    this library. If you modify this library, you may extend this exception
    to your version of the library, but you are not obligated to do so. If
    you do not wish to do so, delete this exception statement from your
    version.
*/

package io.calimero.device;

import static io.calimero.device.ios.InterfaceObject.ADDRESSTABLE_OBJECT;
import static io.calimero.device.ios.InterfaceObject.APPLICATIONPROGRAM_OBJECT;
import static io.calimero.device.ios.InterfaceObject.ASSOCIATIONTABLE_OBJECT;
import static io.calimero.device.ios.InterfaceObject.DEVICE_OBJECT;
import static io.calimero.device.ios.InterfaceObject.KNXNETIP_PARAMETER_OBJECT;
import static io.calimero.knxnetip.servicetype.KNXnetIPHeader.SEARCH_REQ;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Field;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EventObject;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Supplier;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;

import io.calimero.DataUnitBuilder;
import io.calimero.DeviceDescriptor;
import io.calimero.DeviceDescriptor.DD0;
import io.calimero.IndividualAddress;
import io.calimero.KNXException;
import io.calimero.KNXTimeoutException;
import io.calimero.KnxRuntimeException;
import io.calimero.SerialNumber;
import io.calimero.Settings;
import io.calimero.datapoint.Datapoint;
import io.calimero.device.KnxDeviceServiceLogic.LoadState;
import io.calimero.device.ios.DeviceObject;
import io.calimero.device.ios.InterfaceObject;
import io.calimero.device.ios.InterfaceObjectServer;
import io.calimero.device.ios.KnxPropertyException;
import io.calimero.device.ios.KnxipParameterObject;
import io.calimero.device.ios.PropertyEvent;
import io.calimero.device.ios.SecurityObject;
import io.calimero.device.ios.SecurityObject.Pid;
import io.calimero.dptxlator.PropertyTypes;
import io.calimero.internal.Executor;
import io.calimero.knxnetip.KNXnetIPConnection;
import io.calimero.knxnetip.KNXnetIPRouting;
import io.calimero.knxnetip.SecureRouting;
import io.calimero.knxnetip.servicetype.KNXnetIPHeader;
import io.calimero.knxnetip.servicetype.SearchResponse;
import io.calimero.knxnetip.util.DeviceDIB;
import io.calimero.knxnetip.util.HPAI;
import io.calimero.knxnetip.util.ServiceFamiliesDIB;
import io.calimero.knxnetip.util.ServiceFamiliesDIB.ServiceFamily;
import io.calimero.link.AbstractLink;
import io.calimero.link.KNXLinkClosedException;
import io.calimero.link.KNXNetworkLink;
import io.calimero.link.KNXNetworkLinkIP;
import io.calimero.link.KNXNetworkLinkUsb;
import io.calimero.link.medium.KNXMediumSettings;
import io.calimero.log.LogService;
import io.calimero.mgmt.Description;
import io.calimero.mgmt.PropertyAccess;
import io.calimero.mgmt.PropertyAccess.PID;
import io.calimero.mgmt.TransportLayer;
import io.calimero.mgmt.TransportLayerImpl;
import io.calimero.secure.SecureApplicationLayer;
import io.calimero.secure.SecurityControl.DataSecurity;

/**
 * Implementation of a KNX device for common device tasks. This type can either be used directly, with the device logic
 * for process communication and/or management services supplied during construction. Or, extended by a subtype which
 * implements the corresponding service interfaces ({@link ProcessCommunicationService}, {@link ManagementService}).
 * <p>
 * Notes for working with KNX devices: a KNX device can change its individual address. Therefore, do not use the address
 * as identifier.
 *
 * @author B. Malinowsky
 * @see KnxDeviceServiceLogic
 * @see ProcessCommunicationService
 * @see ManagementService
 */
public class BaseKnxDevice implements KnxDevice, AutoCloseable
{
	// The object instance determines which instance of an object type is
	// queried for properties. Always defaults to 1.
	private static final int objectInstance = 1;

	// Values used for manufacturer data DIB
	// PID.MANUFACTURER_ID
	private static final int defMfrId = 0;
	// PID.MANUFACTURER_DATA
	// one element is 4 bytes, value length has to be multiple of that
	// defaults to 'bm2011  '
	private static final byte[] defMfrData = new byte[] { 'b', 'm', '2', '0', '1', '1', ' ', ' ' };

	// property id to distinguish hardware types which are using the same
	// device descriptor mask version
	private static final int pidHardwareType = 78; // PDT Generic 6 bytes

	// service event threading
	static final int INCOMING_EVENTS_THREADED = 1;
	static final int OUTGOING_EVENTS_THREADED = 2;
	int threadingPolicy;

	private boolean taskSubmitted;
	// local queue if a task is currently submitted to our executor service
	private final List<Runnable> tasks = new ArrayList<>();
	private final Lock lock = new ReentrantLock();

	private final String name;
	private final InterfaceObjectServer ios;
	private final Logger logger;

	private final URI iosResource;
	private final char[] iosPwd;
	private static final char[] NoPwd = new char[0];

	TransportLayer tl;
	DeviceSecureApplicationLayer sal;

	private final ProcessCommunicationService process;
	private final ManagementService mgmt;


	private ProcessServiceNotifier procNotifier;
	ManagementServiceNotifier mgmtNotifier;
	private KNXNetworkLink link;

	private static final int deviceMemorySize = 0x10010; // multiple of 4
	private final Memory memory = new ThreadSafeByteArray(deviceMemorySize);

	/**
	 * Creates a new KNX device with a specific device descriptor and a URI locating an interface object server
	 * resource.
	 * Implementation note: iosResource for an encrypted IOS is currently always interpreted as {@link Path}
	 *
	 * @param name KNX device name, used for human-readable naming or device identification
	 * @param dd device descriptor
	 * @param process the device process communication service handler
	 * @param mgmt the device management service handler
	 * @param iosResource location of an interface object server resource to load for this device
	 * @param iosPassword the password to encrypt/decrypt the interface object server resource; an empty char array will
	 *        load/store a plain (unencrypted) interface object server
	 * @throws KnxPropertyException on error setting KNX properties during device initialization
	 */
	public BaseKnxDevice(final String name, final DeviceDescriptor.DD0 dd, final ProcessCommunicationService process,
		final ManagementService mgmt, final URI iosResource, final char[] iosPassword) throws KnxPropertyException
	{
		threadingPolicy = OUTGOING_EVENTS_THREADED;
		this.name = name;
		ios = new InterfaceObjectServer(false);
		ios.addServerListener(this::propertyChanged);
		logger = LogService.getLogger("io.calimero.device." + name);

		this.iosResource = iosResource != null ? iosResource : URI.create("");
		iosPwd = iosPassword;

		this.process = process;
		this.mgmt = mgmt;

		initIos(dd);
		loadDeviceMemory();
	}

	BaseKnxDevice(final String name, final DeviceDescriptor.DD0 dd, final KNXNetworkLink link,
			final ProcessCommunicationService process, final ManagementService mgmt)
			throws KNXLinkClosedException, KnxPropertyException {
		this(name, dd, process, mgmt, null, NoPwd);
		setDeviceLink(link);
	}

	/**
	 * Creates a new KNX device using a {@link KnxDeviceServiceLogic} argument, the device's communication link (and
	 * address) has to be subsequently assigned.
	 *
	 * @param name KNX device name, used for human-readable naming or device identification
	 * @param logic KNX device service logic
	 * @throws KnxPropertyException on error initializing the device KNX properties
	 */
	public BaseKnxDevice(final String name, final KnxDeviceServiceLogic logic) throws KnxPropertyException {
		this(name, logic, null, NoPwd);
	}

	/**
	 * Creates a new KNX device using a {@link KnxDeviceServiceLogic} argument, and a URI locating an interface object
	 * server resource.
	 *
	 * @param name KNX device name, used for human-readable naming or device identification
	 * @param logic KNX device service logic
	 * @param iosResource interface object server resource to load
	 * @param iosPassword password of encrypted interface object server resource, empty char array if plain text
	 * @throws KnxPropertyException on error initializing the device KNX properties
	 */
	public BaseKnxDevice(final String name, final KnxDeviceServiceLogic logic, final URI iosResource,
			final char[] iosPassword) throws KnxPropertyException {
		this(name, DeviceDescriptor.DD0.TYPE_5705, logic, logic, iosResource, iosPassword);
		logic.setDevice(this);
	}

	/**
	 * Creates a new KNX device using a {@link KnxDeviceServiceLogic} and a network link argument.
	 * <p>
	 * The device address is supplied by the link's medium settings, and is only used if the address is not 0.0.0. An
	 * address should be a subnetwork unique device address or a default individual address.
	 *
	 * @param name KNX device name, used for human-readable naming or device identification
	 * @param logic KNX device service logic
	 * @param link the KNX network link this device is attached to
	 * @throws KNXLinkClosedException on closed network link
	 * @throws KnxPropertyException on error initializing the device properties
	 */
	public BaseKnxDevice(final String name, final KnxDeviceServiceLogic logic, final KNXNetworkLink link)
		throws KNXLinkClosedException, KnxPropertyException
	{
		this(name, DeviceDescriptor.DD0.TYPE_5705, link, logic, logic);
	}

	/**
	 * Assigns a new KNX individual address to this device.
	 * <p>
	 * This method sets the new address, and does <i>not</i> perform any other management or
	 * configuration tasks, e.g., ensuring a subnetwork unique device address, or publish the new
	 * address on the network.
	 *
	 * @param address the new device address
	 */
	protected final void setAddress(final IndividualAddress address)
	{
		if (address == null)
			throw new NullPointerException("device address cannot be null");
		if (address.getRawAddress() == 0 || getAddress().equals(address))
			return;

		lock.lock();
		try {
			final KNXNetworkLink link = getDeviceLink();
			if (link != null) {
				final KNXMediumSettings settings = link.getKNXMedium();
				settings.setDeviceAddress(address);
			}

			DeviceObject.lookup(ios).setDeviceAddress(address);

			try {
				setIpProperty(PID.KNX_INDIVIDUAL_ADDRESS, address.toByteArray());
			}
			catch (final KnxPropertyException ignore) {
				// fails if we don't have a KNX IP object
			}
		}
		finally {
			lock.unlock();
		}
	}

	@Override
	public final IndividualAddress getAddress() {
		lock.lock();
		try {
			return DeviceObject.lookup(ios).deviceAddress();
		}
		finally {
			lock.unlock();
		}
	}

	@Override
	public final void setDeviceLink(final KNXNetworkLink link) throws KNXLinkClosedException
	{
		lock.lock();
		try {
			this.link = link;
			// ??? necessary
			if (link == null)
				return;

			final var settings = link.getKNXMedium();
			final var deviceObject = DeviceObject.lookup(ios);
			deviceObject.set(PID.MAX_APDULENGTH, fromWord(settings.maxApduLength()));
			final int medium = settings.getMedium();
			ios.setProperty(InterfaceObject.CEMI_SERVER_OBJECT, objectInstance, PID.MEDIUM_TYPE, 1, 1, (byte) 0, (byte) medium);
			if (medium == KNXMediumSettings.MEDIUM_KNXIP)
				initKnxipProperties();
			else if (medium == KNXMediumSettings.MEDIUM_RF)
				initRfProperties();

			final IndividualAddress address = settings.getDeviceAddress();
			if (address.getDevice() != 0)
				setAddress(address);
			else if (address.getRawAddress() == 0 && !(link instanceof KNXNetworkLinkUsb))
				settings.setDeviceAddress(getAddress());

			if (process instanceof KnxDeviceServiceLogic)
				((KnxDeviceServiceLogic) process).setDevice(this);
			else if (mgmt instanceof KnxDeviceServiceLogic)
				((KnxDeviceServiceLogic) mgmt).setDevice(this);

			tl = new TransportLayerImpl(link, true);
			if (sal != null)
				sal.close();
			sal = new DeviceSecureApplicationLayer(this);
			ensureInitializedSeqNumber();
			resetNotifiers();
		}
		finally {
			lock.unlock();
		}
	}

	private static final int SeqSize = 6;

	private void ensureInitializedSeqNumber() throws KNXLinkClosedException {
		final var secif = SecurityObject.lookup(getInterfaceObjectServer());
		if (!secif.isLoaded() || !sal.isSecurityModeEnabled())
			return;
		if (unsigned(secif.get(SecurityObject.Pid.SequenceNumberSending)) > 1)
			return;
		secif.set(Pid.SequenceNumberSending, sixBytes(1).array());

		final var requests = new ArrayList<CompletableFuture<Void>>();
		final var table = ByteBuffer.wrap(secif.get(Pid.SecurityIndividualAddressTable));
		while (table.hasRemaining()) {
			final var remote = new IndividualAddress(table.getShort() & 0xffff);
			table.get(new byte[SeqSize]);
			try {
				requests.add(sal.sendSyncRequest(remote, false));
				final int maxRequests = 5;
				if (requests.size() >= maxRequests)
					break;
			}
			catch (final KNXTimeoutException e) {}
		}

		try {
			final var success = new CompletableFuture<>();
			requests.forEach(r -> r.thenAccept(success::complete));
			success.orTimeout(6, TimeUnit.SECONDS).join();
		}
		catch (final RuntimeException e) {
			logger.warn("awaiting sync.res for initializing sequence number", e.getCause());
		}
	}

	@Override
	public final KNXNetworkLink getDeviceLink()
	{
		lock.lock();
		try {
			return link;
		}
		finally {
			lock.unlock();
		}
	}

	@Override
	public final InterfaceObjectServer getInterfaceObjectServer()
	{
		return ios;
	}

	/**
	 * Thread-safe access to device memory, individual reads/writes are guaranteed to be thread-safe.
	 *
	 * @return device memory representation for thread-safe memory access
	 */
	@Override
	public Memory deviceMemory() { return memory; }

	/**
	 * {@return the task executor providing the threads to run the process communication and
	 *         management services}
	 */
	public ExecutorService taskExecutor()
	{
		return Executor.executor();
	}

	public final TransportLayer transportLayer() { return tl; }

	public final SecureApplicationLayer secureApplicationLayer() { return sal; }

	public final void addGroupObject(final Datapoint dp, final DataSecurity security, final boolean update) {
		final int goSecurity = groupObjectSecurity(security);

		final var group = dp.getMainAddress();
		final var optGaIdx = KnxDeviceServiceLogic.groupAddressIndex(ios, group);
		if (optGaIdx.isPresent()) {
			final int idx = optGaIdx.orElseThrow();
			final long sec = unsigned(ios.getProperty(InterfaceObject.SECURITY_OBJECT, objectInstance,
					SecurityObject.Pid.GoSecurityFlags, idx, 1));
			if (sec < goSecurity)
				ios.setProperty(InterfaceObject.SECURITY_OBJECT, objectInstance, SecurityObject.Pid.GoSecurityFlags,
						idx, 1, (byte) goSecurity);
		}
		else {
			final int lastGaIdx = (int) unsigned(
					ios.getProperty(ADDRESSTABLE_OBJECT, objectInstance, PropertyAccess.PID.TABLE, 0, 1));
			final int newGaIdx = lastGaIdx + 1;
			ios.setProperty(ADDRESSTABLE_OBJECT, objectInstance, PropertyAccess.PID.TABLE, newGaIdx, 1,
					group.toByteArray());
			ios.setProperty(InterfaceObject.SECURITY_OBJECT, objectInstance, SecurityObject.Pid.GoSecurityFlags,
					newGaIdx, 1, (byte) goSecurity);

			final boolean bigAssocTable = isBigAssocTable();

			final byte[] table = ios.getProperty(ASSOCIATIONTABLE_OBJECT, objectInstance, PropertyAccess.PID.TABLE, 1,
					Integer.MAX_VALUE);
			final var buffer = ByteBuffer.wrap(table);
			int maxGoIdx = 0;
			while (buffer.hasRemaining()) {
				final int goIdx;
				if (bigAssocTable) {
					buffer.getShort();
					goIdx = buffer.getShort() & 0xffff;
				}
				else {
					buffer.get();
					goIdx = buffer.get() & 0xff;
				}
				maxGoIdx = Math.max(maxGoIdx, goIdx);
			}

			final int newGoIdx = maxGoIdx + 1;
			final int assocEntrySize = bigAssocTable ? 4 : 2;
			final int newAssocIdx = table.length / assocEntrySize + 1;
			final var bb = ByteBuffer.allocate(assocEntrySize);
			if (bigAssocTable)
				bb.putShort((short) newGaIdx).putShort((short) newGoIdx);
			else
				bb.put((byte) newGaIdx).put((byte) newGoIdx);
			final byte[] assoc = bb.array();
			ios.setProperty(ASSOCIATIONTABLE_OBJECT, objectInstance, PropertyAccess.PID.TABLE, newAssocIdx, 1, assoc);

			final byte[] groupObjectDescriptor;
			final int groupObjTablePdt = groupObjTablePdt();
			groupObjectDescriptor = switch (groupObjTablePdt) {
				case PropertyTypes.PDT_GENERIC_02 ->
						KnxDeviceServiceLogic.groupObjectDescriptor(dp.getDPT(), dp.getPriority(), false, update);
				case PropertyTypes.PDT_GENERIC_03 ->
						KnxDeviceServiceLogic.groupObjectDescriptor3Bytes(dp.getDPT(), dp.getPriority(), false, update);
				default ->
						throw new KnxRuntimeException("group object table: PID Table PDT " + groupObjTablePdt + " not supported");
			};
			ios.setProperty(InterfaceObject.GROUP_OBJECT_TABLE_OBJECT, 1, PID.TABLE, newGoIdx, 1,
					groupObjectDescriptor);
		}
	}

	// prepare properties usually required for ETS download
	public void identification(final DeviceDescriptor.DD0 dd, final int manufacturerId, final SerialNumber serialNumber,
			final byte[] hardwareType, final byte[] programVersion, final byte[] fdsk) {
		final var deviceObject = DeviceObject.lookup(ios);
		// matching device descriptor to indicate BCU
		deviceObject.set(PID.DEVICE_DESCRIPTOR, dd.toByteArray());

		final ByteBuffer memAddr = ByteBuffer.allocate(4).putInt(dd == DD0.TYPE_0705 ? 0x4000 : 0x0116);
		ios.setProperty(ADDRESSTABLE_OBJECT, PID.TABLE_REFERENCE, 1, 1, memAddr.array());

		deviceObject.set(PID.MANUFACTURER_ID, (byte) (manufacturerId >> 8), (byte) manufacturerId);
		deviceObject.set(PID.SERIAL_NUMBER, serialNumber.array());
		deviceObject.set(78, hardwareType);

		ios.setProperty(APPLICATIONPROGRAM_OBJECT, 1, PID.PROGRAM_VERSION, 1, 1, programVersion);

		// fdsk for secure device download
		SecurityObject.lookup(ios).set(SecurityObject.Pid.ToolKey, fdsk);
	}

	protected static final class RoutingConfig {
		private final InetAddress mcGroup;
		private final byte[] groupKey;
		private final Duration latencyTolerance;

		RoutingConfig(final InetAddress mcGroup) {
			this.mcGroup = mcGroup;
			groupKey = new byte[0];
			latencyTolerance = Duration.ZERO;
		}

		RoutingConfig(final InetAddress mcGroup, final byte[] groupKey, final Duration latencyTolerance) {
			this.mcGroup = mcGroup;
			this.groupKey = groupKey;
			this.latencyTolerance = latencyTolerance;
		}

		public InetAddress multicastGroup() { return mcGroup; }

		public boolean secureRouting() { return groupKey.length == 16; }

		public byte[] groupKey() { return groupKey.clone(); }

		public Duration latencyTolerance() { return latencyTolerance; }

		@Override
		public String toString() {
			final String secure = secureRouting() ? new String(Character.toChars(0x1F512)) + " " : "";
			return String.format("%smcast %s", secure, mcGroup.getHostAddress());
		}
	}

	protected void ipRoutingConfigChanged(final RoutingConfig config) {
		final var oldLink = getDeviceLink();
		final var settings = oldLink.getKNXMedium();

		try {
			final var routing = connectionOfLink();
			final var netif = routing.networkInterface();

			final KNXNetworkLink newLink;
			if (config.secureRouting())
				newLink = KNXNetworkLinkIP.newSecureRoutingLink(netif, config.multicastGroup(), config.groupKey(),
						config.latencyTolerance(), settings);
			else
				newLink = KNXNetworkLinkIP.newRoutingLink(netif, config.multicastGroup(), settings);
			setDeviceLink(newLink);
			oldLink.close();
		}
		catch (ReflectiveOperationException | KNXException | RuntimeException e) {
			logger.warn("error setting device routing link ({})", config, e);
		}
		catch (final InterruptedException e) {
			logger.warn("interrupted group sync for new device routing link ({})", config, e);
			Thread.currentThread().interrupt();
		}
	}

	private static ByteBuffer sixBytes(final long num) {
		return ByteBuffer.allocate(6).putShort((short) (num >> 32)).putInt((int) num).flip();
	}

	private static int groupObjectSecurity(final DataSecurity security) {
		return security == DataSecurity.AuthConf ? 3 : security.ordinal();
	}

	private static long unsigned(final byte[] data) {
		long v = 0;
		for (final byte b : data)
			v = (v << 8) + (b & 0xff);
		return v;
	}

	@Override
	public void close() {
		if (sal != null)
			sal.close();

		saveDeviceMemory();
		saveIos();
	}

	private void saveIos() {
		if ("".equals(iosResource.toString()))
			return;

		try {
			logger.debug("saving interface object server to {}", iosResource);
			if (iosPwd.length > 0)
				saveEncryptedIos(iosPwd);
			else
				ios.saveInterfaceObjects(iosResource.toString());
		}
		catch (GeneralSecurityException | IOException | KNXException | RuntimeException e) {
			logger.error("saving interface object server", e);
		}
	}

	private void saveEncryptedIos(final char[] pwd) throws GeneralSecurityException, IOException, KNXException {
		final var os = Files.newOutputStream(Path.of(iosResource));
		final var generatedSalt = new byte[16];
		final var cipher = iosCipher(pwd, generatedSalt, null);
		try (var cos = new CipherOutputStream(os, cipher)) {
			os.write(generatedSalt);
			os.write(cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV());
			ios.saveInterfaceObjects(cos);
		}
	}

	private void loadEncryptedIos(final char[] pwd) throws GeneralSecurityException, IOException, KNXException {
		final var is = Files.newInputStream(Path.of(iosResource));
		try (var cis = new CipherInputStream(is, iosCipher(pwd, is.readNBytes(16), is.readNBytes(16)))) {
			ios.loadInterfaceObjects(cis);
		}
	}

	// salt is input param on decrypt, output param on encrypt
	// useIv is null on encrypt
	private static Cipher iosCipher(final char[] pwd, final byte[] salt, final byte[] useIv)
			throws GeneralSecurityException {
		final boolean encrypt = useIv == null;
		if (encrypt)
			new SecureRandom().nextBytes(salt);

		final var spec = new PBEKeySpec(pwd, salt, 65_536, 256);
		final var tmp = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec);
		final var secret = new SecretKeySpec(tmp.getEncoded(), "AES");

		final var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		if (encrypt)
			cipher.init(Cipher.ENCRYPT_MODE, secret);
		else
			cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(useIv));
		return cipher;
	}

	@Override
	public String toString()
	{
		return name + " " + getAddress();
	}

	private static final AtomicLong taskCounter = new AtomicLong();

	 <T> void dispatch(final EventObject e, final Supplier<ServiceResult<T>> dispatch,
		final BiConsumer<EventObject, ServiceResult<T>> respond)
	{
		final long start = System.nanoTime();
		final long taskId = taskCounter.incrementAndGet();
		if (threadingPolicy == INCOMING_EVENTS_THREADED) {
			submitTask(taskId, () -> {
				try {
					Optional.ofNullable(dispatch.get()).ifPresent(sr -> respond.accept(e, sr));
				}
				catch (final RuntimeException rte) {
					logger.error("error executing dispatch/respond task {}", taskId, rte);
				}
				finally {
					taskDone(taskId, start);
				}
			});
		}
		else {
			Optional.ofNullable(dispatch.get()).ifPresent(sr -> submitTask(taskId, () -> {
				try {
					respond.accept(e, sr);
				}
				catch (final RuntimeException rte) {
					logger.error("error executing respond task {}", taskId, rte);
				}
				finally {
					taskDone(taskId, start);
				}
			}));
		}
	}

	Logger logger()
	{
		return logger;
	}

	private void initIos(final DD0 dd) {
		if (loadIosFromResource())
			return;

		// initialization continues here only if no resource was loaded

		final var addressTable = ios.addInterfaceObject(ADDRESSTABLE_OBJECT);
		initTableProperties(addressTable, dd == DD0.TYPE_5705 ? 0x4000 : 0x0116, dd);

		final var assocTable = ios.addInterfaceObject(ASSOCIATIONTABLE_OBJECT);
		initTableProperties(assocTable, 0x1000, dd);

		final var groupObjectTable = ios.addInterfaceObject(InterfaceObject.GROUP_OBJECT_TABLE_OBJECT);
		initTableProperties(groupObjectTable, 0x3000, dd);
		final int pidGODiagnostics = 66;
		ios.setDescription(new Description(groupObjectTable.getIndex(), 0, pidGODiagnostics,
				PropertyTypes.PDT_FUNCTION, 0, true, 0, 1, 3, 3), true);

		final var appObject = ios.addInterfaceObject(APPLICATIONPROGRAM_OBJECT);
		initTableProperties(appObject, 0x4000, dd);

		ios.addInterfaceObject(InterfaceObject.APPLICATION_PROGRAM2);
		ios.addInterfaceObject(InterfaceObject.CEMI_SERVER_OBJECT);
		ios.addInterfaceObject(InterfaceObject.SECURITY_OBJECT);

		initDeviceInfo(dd);
	}

	private boolean loadIosFromResource() {
		if ("".equals(iosResource.toString()))
			return false;
		try {
			ios.removeInterfaceObject(ios.getInterfaceObjects()[0]);
			logger.debug("loading interface object server from {}", iosResource);
			if (iosPwd.length > 0 && Path.of(iosResource).toFile().exists())
				loadEncryptedIos(iosPwd);
			else
				ios.loadInterfaceObjects(iosResource.toString());
			return true;
		}
		catch (final UncheckedIOException e) {
			final var cause = e.getCause();
			if (cause instanceof FileNotFoundException)
				logger.debug("no interface object server resource, create resource on closing device: {}",
						cause.getMessage());
			else
				logger.info("could not open {}, create resource on closing device ({})", iosResource,
						cause.getMessage());
			// re-add device object
			ios.addInterfaceObject(InterfaceObject.DEVICE_OBJECT);
			return false;
		}
		catch (final GeneralSecurityException | IOException | KNXException e) {
			throw new KnxRuntimeException("loading interface object server", e);
		}
	}

	private static final int objectTypeDeviceMemory = 54321;
	private static final int pidDeviceMemory = 201;

	private void loadDeviceMemory() {
		if ("".equals(iosResource.toString()))
			return;

		try {
			final var io = ios.lookup(objectTypeDeviceMemory, 1);
			try {
				final byte[] bytes = ios.getProperty(objectTypeDeviceMemory, 1, pidDeviceMemory, 1, Integer.MAX_VALUE);
				ios.removeInterfaceObject(io);
				if (bytes.length != memory.size())
					logger.warn("loaded {} bytes from {}, available device memory is {} bytes", bytes.length,
							iosResource, memory.size());
				memory.set(0, bytes);
			}
			catch (final KnxPropertyException e) {
				logger.warn("loading device memory from {}", iosResource, e);
			}
	}
		catch (final KnxPropertyException e) { // lookup failed, no device memory stored
		}
	}

	private void saveDeviceMemory() {
		if ("".equals(iosResource.toString()))
			return;

		try {
			logger.debug("saving device memory to {}", iosResource);
			final byte[] bytes = memory.get(0, memory.size());
			ios.addInterfaceObject(objectTypeDeviceMemory);
			ios.setProperty(objectTypeDeviceMemory, 1, pidDeviceMemory, 1, bytes.length / 4, bytes);
		}
		catch (final KnxPropertyException e) {
			logger.warn("saving device memory to {}", iosResource, e);
		}
	}

	private void initTableProperties(final InterfaceObject io, final int memAddress, final DD0 dd0) {
		final int idx = io.getIndex();
		ios.setProperty(idx, PID.LOAD_STATE_CONTROL, 1, 1, (byte) LoadState.Loaded.ordinal());
		ios.setProperty(idx, PID.TABLE_REFERENCE, 1, 1, ByteBuffer.allocate(4).putInt(memAddress).array());

		final boolean systemB = dd0.firmwareVersion() == 0xB;
		final boolean bigAssocTable = dd0 == DD0.TYPE_0300 || systemB;
		final int pdt;
		if (io.getType() == ASSOCIATIONTABLE_OBJECT && bigAssocTable)
			pdt = PropertyTypes.PDT_GENERIC_04;
		else if (io.getType() == InterfaceObject.GROUP_OBJECT_TABLE_OBJECT)
			pdt = systemB ? PropertyTypes.PDT_GENERIC_02 : dd0 == DD0.TYPE_0300 ? PropertyTypes.PDT_GENERIC_06
					: PropertyTypes.PDT_GENERIC_03;
		else
			pdt = PropertyTypes.PDT_GENERIC_02;
		ios.setDescription(new Description(idx, 0, PID.TABLE, 0, pdt, true, 0, 100, 3, 3), true);

		final int elems = 4;
		ios.setProperty(idx, PID.MCB_TABLE, 1, elems, new byte[elems * 8]);
	}

	private boolean isBigAssocTable() {
		final var dd0 = DeviceObject.lookup(ios).deviceDescriptor();
		final boolean systemB = dd0.firmwareVersion() == 0xB;
		final boolean bigAssocTable = dd0 == DD0.TYPE_0300 || systemB;
		return bigAssocTable;
	}

	private int groupObjTablePdt() {
		final var dd0 = DeviceObject.lookup(ios).deviceDescriptor();
		final boolean systemB = dd0.firmwareVersion() == 0xB;
		final int pdt = systemB ? PropertyTypes.PDT_GENERIC_02 : dd0 == DD0.TYPE_0300 ? PropertyTypes.PDT_GENERIC_06
				: PropertyTypes.PDT_GENERIC_03;
		return pdt;
	}

	private void initDeviceInfo(final DD0 dd) throws KnxPropertyException
	{
		// Device Object settings

		final var deviceObject = DeviceObject.lookup(ios);

		final byte[] desc = name.getBytes(StandardCharsets.ISO_8859_1);
		ios.setProperty(DEVICE_OBJECT, objectInstance, PID.DESCRIPTION, 1, desc.length, desc);

		final String[] sver = Settings.getLibraryVersion().split("\\.| |-", 0);
		final int ver = Integer.parseInt(sver[0]) << 6 | Integer.parseInt(sver[1]);
		deviceObject.set(PID.VERSION, fromWord(ver));

		final int indAddressWriteEnable = 0x04;
		deviceObject.set(PID.SERVICE_CONTROL, (byte) 0, (byte) indAddressWriteEnable);

		// Firmware Revision
		final int firmwareRev = 1;
		deviceObject.set(PID.FIRMWARE_REVISION, (byte) firmwareRev);

		// Serial Number
		final byte[] sno = new byte[6];
		deviceObject.set(PID.SERIAL_NUMBER, sno);

		final int verifyModeOn = 0; // 0x04 if on
		deviceObject.set(PID.DEVICE_CONTROL, (byte) verifyModeOn);

		// device status is not in programming mode
		deviceObject.set(PID.PROGMODE, (byte) 0);
		// Programming Mode (memory address 0x60) set off
		memory.set(0x60, 0);

		deviceObject.set(PID.MANUFACTURER_ID, fromWord(defMfrId));
		ios.setProperty(DEVICE_OBJECT, objectInstance, PID.MANUFACTURER_DATA, 1, defMfrData.length / 4, defMfrData);

		// Hardware Type
		final byte[] hwType = new byte[6];
		deviceObject.set(pidHardwareType, hwType);

		// device descriptor
		deviceObject.set(PID.DEVICE_DESCRIPTOR, dd.toByteArray());
		// validity check on mask and hardware type octets (AN059v3, AN089v3)
		final int maskVersion = dd.maskVersion();
		if ((maskVersion == 0x25 || maskVersion == 0x0705) && hwType[0] != 0) {
			logger.error("manufacturer-specific device identification of hardware type should be 0 for this mask!");
		}

		// don't confuse this with PID_MAX_APDU_LENGTH of the Router Object (PID = 58!!)
		ios.setDescription(new Description(0, 0, PID.MAX_APDULENGTH, 0, 0, false, 0, 1, 3, 0), true);
		// can be between 15 and 254 bytes (255 is Escape code for extended L_Data frames)
		deviceObject.set(PID.MAX_APDULENGTH, fromWord(254));

		// default TP1 address
		deviceObject.setDeviceAddress(new IndividualAddress(0x02ff));

		// Order Info
		final byte[] orderInfo = new byte[10]; // PDT Generic 10 bytes
		deviceObject.set(PID.ORDER_INFO, orderInfo);

		// PEI Types
		// in devices without PEI, value is 0
		// PEI type 1: Illegal adapter
		// PEI type 10, 12, 14 and 16: serial interface to application module
		// PEI type 10: protocol on top of FT1.2
		// PEI type 2, 4, 6, 8, 17: parallel I/O (17 = programmable I/O)
		final int peiType = 0; // unsigned char

		// Physical PEI
		deviceObject.set(PID.PEI_TYPE, (byte) peiType);

		final int pidDownloadCounter = 30;
		deviceObject.set(pidDownloadCounter, (byte) 0, (byte) 0);

		// cEMI server object setttings

		// set default medium to TP1 (Bit 1 set)
		ios.setProperty(InterfaceObject.CEMI_SERVER_OBJECT, objectInstance, PID.MEDIUM_TYPE, 1, 1, new byte[] { 0, 2 });


		// Application Program Object settings

		// Required PEI Type
		final int requiredPeiType = 0; // unsigned char
		ios.setProperty(APPLICATIONPROGRAM_OBJECT, objectInstance, PID.PEI_TYPE, 1, 1, fromByte(requiredPeiType));

		final int[] runStateEnum = {
			0, // Halted or not loaded
			1, // Running
			2, // Ready for being executed
			3, // Terminated (app only starts again after restart/device reset)
			4, // Starting, required for apps with >2 s startup time
			5, // Shutting down
		};
		final int runState = runStateEnum[1];
		// Run State
		ios.setProperty(APPLICATIONPROGRAM_OBJECT, objectInstance, PID.RUN_STATE_CONTROL, 1, 1, (byte) runState);

		// Application ID
		final byte[] applicationVersion = new byte[5]; // PDT Generic 5 bytes
		ios.setProperty(APPLICATIONPROGRAM_OBJECT, objectInstance, PID.PROGRAM_VERSION, 1, 1, applicationVersion);
	}

	private void setIpProperty(final int propertyId, final byte... data)
	{
		ios.setProperty(KNXNETIP_PARAMETER_OBJECT, objectInstance, propertyId, 1, 1, data);
	}

	private KNXnetIPRouting connectionOfLink() throws ReflectiveOperationException {
		final KNXnetIPRouting conn = accessField(AbstractLink.class, "conn", link);
		if (conn == null)
			throw new KnxRuntimeException("no KNX IP routing connection found in link " + link.getName(), null);
		return conn;
	}

	@SuppressWarnings("unchecked")
	private static <T, U> T accessField(final Class<? extends U> clazz, final String field, final U obj)
		throws ReflectiveOperationException, SecurityException {
		Class<? extends U> cl = (Class<? extends U>) obj.getClass();
		while (cl != null && !clazz.equals(cl))
			cl = (Class<? extends U>) cl.getSuperclass();
		if (cl == null)
			return null;
		final Field f = cl.getDeclaredField(field);
		f.setAccessible(true);
		return (T) f.get(obj);
	}

	private void resetNotifiers() throws KNXLinkClosedException
	{
		if (procNotifier != null)
			procNotifier.close();
		procNotifier = link != null && process != null ? new ProcessServiceNotifier(this, process) : null;

		if (mgmtNotifier != null)
			mgmtNotifier.close();
		mgmtNotifier = link != null && mgmt != null ? new ManagementServiceNotifier(this, mgmt) : null;
	}

	private void initKnxipProperties() {
		if (!lookup(KNXNETIP_PARAMETER_OBJECT)) {
			ios.addInterfaceObject(KNXNETIP_PARAMETER_OBJECT);

			final var knxipObject = KnxipParameterObject.lookup(ios, objectInstance);

			knxipObject.set(PID.PROJECT_INSTALLATION_ID, fromWord(0));
			knxipObject.set(PID.CURRENT_IP_ASSIGNMENT_METHOD, (byte) 1);
			knxipObject.set(PID.IP_ASSIGNMENT_METHOD, (byte) 1);
			knxipObject.set(PID.IP_CAPABILITIES, (byte) 0);

			// set default ttl
			knxipObject.set(PID.TTL, (byte) 16);

			// PID.KNXNETIP_DEVICE_CAPABILITIES
			// Bits LSB to MSB: 0 Device Management, 1 Tunneling, 2 Routing, 3 Remote Logging,
			// 4 Remote Configuration and Diagnosis, 5 Object Server
			final int deviceCaps = 4;
			knxipObject.set(PID.KNXNETIP_DEVICE_CAPABILITIES, fromWord(deviceCaps));

			knxipObject.setFriendlyName(name);
		}

		setIpProperty(PID.KNX_INDIVIDUAL_ADDRESS, getAddress().toByteArray());

		// pull out IP info from KNX IP protocol
		byte[] ip = new byte[4];
		final byte[] mask = new byte[4];
		byte[] mac = new byte[6];
		byte[] mcast = new byte[4];
		try {
			final KNXnetIPRouting conn = connectionOfLink();
			mcast = conn.getRemoteAddress().getAddress().getAddress();

			NetworkInterface netif = conn.networkInterface();
			Optional<InterfaceAddress> addr = Optional.empty();

			// workaround to verify that interface is actually configured
			if (NetworkInterface.getByName(netif.getName()) != null) {
				final var addresses = netif.getInterfaceAddresses();
				addr = addresses.stream().filter(a -> a.getAddress() instanceof Inet4Address).findFirst();
			}
			else {
				// best-effort lookup of default interface
				for (final var nif : Collections.list(NetworkInterface.getNetworkInterfaces())) {
					try {
						if (nif.isUp() && nif.supportsMulticast() && !nif.isLoopback() && !nif.isPointToPoint()) {
							final var addresses = nif.getInterfaceAddresses();
							addr = addresses.stream().filter(a -> a.getAddress() instanceof Inet4Address).findFirst();
							if (addr.isPresent()) {
								netif = nif;
								break;
							}
						}
					}
					catch (final SocketException e) {}
				}
			}

			if (addr.isPresent()) {
				ip = addr.get().getAddress().getAddress();
				final int prefixLength = addr.get().getNetworkPrefixLength();
				final long defMask = 0xffffffffL;
				final long intMask = defMask ^ (defMask >> prefixLength);
				ByteBuffer.wrap(mask).putInt((int) intMask);
			}

			mac = Optional.ofNullable(netif.getHardwareAddress()).orElse(mac);

			final var lookup = MethodHandles.privateLookupIn(KNXnetIPRouting.class, MethodHandles.lookup());
			final var callback = lookup.findVarHandle(KNXnetIPRouting.class, "searchRequestCallback",
					BiFunction.class);
			callback.setVolatile(conn, (BiFunction<KNXnetIPHeader, ByteBuffer, SearchResponse>) this::ipSearchRequest);

			if (conn instanceof final SecureRouting secRouting) {
				// TODO set actual key
				setIpProperty(KnxipParameterObject.Pid.BackboneKey, new byte[16]);

				final int bits = 1 << ServiceFamily.Routing.id();
				// function property
				setIpProperty(KnxipParameterObject.Pid.SecuredServiceFamilies, new byte[] { 0, (byte) bits });

				final long ms = secRouting.latencyTolerance().toMillis();
				final byte[] msData = new byte[] { (byte) (ms >> 8), (byte) (ms & 0xff)};
				setIpProperty(KnxipParameterObject.Pid.LatencyTolerance, msData);

				final double frac = secRouting.syncLatencyFraction();
				setIpProperty(KnxipParameterObject.Pid.SyncLatencyFraction, (byte) (frac * 255));
			}
		}
		catch (ReflectiveOperationException | IOException | RuntimeException e) {
			logger.warn("initializing KNX IP properties, {}", e.toString());
		}

		final var knxipObject = KnxipParameterObject.lookup(ios, objectInstance);
		knxipObject.populateWithDefaults();

		setIpProperty(PID.CURRENT_IP_ADDRESS, ip);
		setIpProperty(PID.CURRENT_SUBNET_MASK, mask);

		final byte[] gw = new byte[4];
		setIpProperty(PID.CURRENT_DEFAULT_GATEWAY, gw);
		setIpProperty(PID.IP_ADDRESS, ip);
		setIpProperty(PID.SUBNET_MASK, mask);
		setIpProperty(PID.DEFAULT_GATEWAY, gw);
		setIpProperty(PID.MAC_ADDRESS, mac);
		if (!Arrays.equals(mcast, new byte[4]))
			setIpProperty(PID.ROUTING_MULTICAST_ADDRESS, mcast);
	}

	private void initRfProperties() {
		if (!lookup(InterfaceObject.RF_MEDIUM_OBJECT))
			ios.addInterfaceObject(InterfaceObject.RF_MEDIUM_OBJECT);
	}

	private boolean lookup(final int ioType) {
		boolean found = false;
		for (final InterfaceObject io : ios.getInterfaceObjects())
			found |= io.getType() == ioType;
		return found;
	}

	private SearchResponse ipSearchRequest(final KNXnetIPHeader h, final ByteBuffer data) {
		return searchResponse(h, data);
	}

	private SearchResponse searchResponse(final KNXnetIPHeader h, final ByteBuffer data) {
		final int svc = h.getServiceType();
		if (svc != SEARCH_REQ)
			return null;

		final DeviceObject deviceObject = DeviceObject.lookup(ios);
		final var deviceAddress = deviceObject.deviceAddress();
		final var progmode = deviceObject.programmingMode();
		final var sno = deviceObject.serialNumber();

		final var knxipObject = KnxipParameterObject.lookup(ios, 1);
		final var ip = knxipObject.inetAddress(PropertyAccess.PID.CURRENT_IP_ADDRESS);
		final var mcast = knxipObject.inetAddress(PropertyAccess.PID.ROUTING_MULTICAST_ADDRESS);
		final var deviceName = knxipObject.friendlyName();
		final var projectInstId = (int) unsigned(knxipObject.get(PropertyAccess.PID.PROJECT_INSTALLATION_ID));
		final var mac = knxipObject.get(PropertyAccess.PID.MAC_ADDRESS);

		final var deviceDib = new DeviceDIB(deviceName, progmode ? 1 : 0, projectInstId,
				KNXMediumSettings.MEDIUM_KNXIP, deviceAddress, sno, mcast, mac);
		final ServiceFamiliesDIB svcFamilies = new ServiceFamiliesDIB(Map.of(ServiceFamily.Core, 1));

		final HPAI ctrlEndpoint = new HPAI(ip, KNXnetIPConnection.DEFAULT_PORT);
		return new SearchResponse(ctrlEndpoint, deviceDib, svcFamilies);
	}

	private void propertyChanged(final PropertyEvent pe) {
		try {
			if (pe.getInterfaceObject().getType() == InterfaceObject.KNXNETIP_PARAMETER_OBJECT) {
				final int pid = pe.getPropertyId();
				if (pid == PID.TTL) {
					final KNXnetIPRouting conn = connectionOfLink();
					conn.setHopCount(pe.getNewData()[0]);
				}
				else if (pid == PID.KNX_INDIVIDUAL_ADDRESS)
					setAddress(new IndividualAddress(pe.getNewData()));
			}
		}
		catch (ReflectiveOperationException | RuntimeException e) {
			logger.warn("updating {} PID {} with [{}]: {}", pe.getInterfaceObject(), pe.getPropertyId(),
					DataUnitBuilder.toHex(pe.getNewData(), ""), e.toString());
		}
	}

	private void submitTask(final long taskId, final Runnable task)
	{
		logger.trace("queue task " + taskId);
		lock.lock();
		try {
			if (taskSubmitted)
				tasks.add(task);
			else {
				taskSubmitted = true;
				taskExecutor().submit(task);
			}
		}
		finally {
			lock.unlock();
		}
	}

	private void taskDone(final long taskId, final long start) {
		final long total = System.nanoTime() - start;
		final long ms = total / 1_000_000L;
		if (ms > 5000)
			logger.warn("task {} took suspiciously long ({} ms)", taskId, ms);

		lock.lock();
		try {
			if (tasks.isEmpty())
				taskSubmitted = false;
			else
				taskExecutor().submit(tasks.remove(0));
		}
		finally {
			lock.unlock();
		}
	}

	private static byte[] fromWord(final int word)
	{
		return new byte[] { (byte) (word >> 8), (byte) word };
	}

	private static byte[] fromByte(final int uchar)
	{
		return new byte[] { (byte) uchar };
	}
}
