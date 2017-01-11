/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2011, 2017 B. Malinowsky

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

package tuwien.auto.calimero.device;

import static tuwien.auto.calimero.device.ios.InterfaceObject.DEVICE_OBJECT;

import java.net.URL;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.EventObject;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;

import tuwien.auto.calimero.DeviceDescriptor;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.Settings;
import tuwien.auto.calimero.device.ios.InterfaceObject;
import tuwien.auto.calimero.device.ios.InterfaceObjectServer;
import tuwien.auto.calimero.device.ios.KNXPropertyException;
import tuwien.auto.calimero.link.KNXLinkClosedException;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.mgmt.Description;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.xml.KNXMLException;

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
public class BaseKnxDevice implements KnxDevice
{
	// can be between 15 and 254 bytes (255 is Escape code for extended L_Data frames)
	private static final int maxApduLength = 15;

	private static final String propDefinitionsResource = "/properties.xml";
	// The object instance determines which instance of an object type is
	// queried for properties. Always defaults to 1.
	private static final int objectInstance = 1;

	// PID.PROGMODE
	private static final int defDeviceStatus = 0;
	// PID.SERIAL_NUMBER
	private static final byte[] defSerialNumber = new byte[6];

	// Values used for manufacturer data DIB

	// PID.MANUFACTURER_ID
	private static final int defMfrId = 0;
	// PID.MANUFACTURER_DATA
	// one element is 4 bytes, value length has to be multiple of that
	// defaults to 'bm2011  '
	private static final byte[] defMfrData = new byte[] { 'b', 'm', '2', '0', '1', '1', ' ', ' ' };


	// service event threading
	static final int INCOMING_EVENTS_THREADED = 1;
	static final int OUTGOING_EVENTS_THREADED = 2;
	int threadingPolicy;

	// process & mgmt communication service tasks are processed as follows:
	//  *) producer / consumer pattern
	//  *) in-order task processing per producer
	//  *) sequential task processing per producer
	private static final ThreadFactory factory = Executors.defaultThreadFactory();
	private static final ThreadPoolExecutor executor = new ThreadPoolExecutor(0, 1, 10, TimeUnit.SECONDS,
			new LinkedBlockingQueue<Runnable>(), (r) -> {
				final Thread t = factory.newThread(r);
				t.setName("Calimero Device Task (" + t.getName() + ")");
				t.setDaemon(true); // on shutdown, we won't execute any remaining tasks
				return t;
			});

	private boolean taskSubmitted;
	// local queue if a task is currently submitted to our executor service
	private final List<Runnable> tasks = new ArrayList<>(5);

	private final String name;
	private final DeviceDescriptor dd;
	private final InterfaceObjectServer ios;
	private final Logger logger;

	private IndividualAddress self;
	private ProcessServiceNotifier procNotifier;
	private ManagementServiceNotifier mgmtNotifier;
	private KNXNetworkLink link;

	BaseKnxDevice(final String name, final DeviceDescriptor dd)
	{
		threadingPolicy = OUTGOING_EVENTS_THREADED;
		this.name = name;
		this.dd = dd;
		ios = new InterfaceObjectServer(false);
		logger = LogService.getLogger("calimero.device." + name);

		// check property definitions for encoding support before we init basic properties
		try {
			final URL resource = this.getClass().getResource(propDefinitionsResource);
			if (resource != null)
				ios.loadDefinitions(resource.toString());
		}
		catch (KNXException | KNXMLException e) {
			// using the default resource ID, we cannot expect to always find the resource
			logger.info("could not load the Interface Object Server KNX property definitions");
		}
	}

	/**
	 * Creates a new KNX device, requiring any subtype to initialize the service logic during construction.
	 * <p>
	 * The device address is either a configured subnetwork unique device address, or the default individual address if
	 * no address was assigned to the device yet. The default individual device address consists of a medium dependent
	 * default subnetwork address and the device address for unregistered devices. Unregistered devices are identified
	 * by using the device address 0xff, a value reserved for this purpose. The subnetwork address part describes the
	 * individual address' <i>area</i> and <i>line</i>. The default subnetwork address by medium is as follows, listed
	 * as <i>Medium</i>: <i>Subnetwork address</i>:
	 * <ul>
	 * <li>TP 1: 0x02</li>
	 * <li>PL 110: 0x04</li>
	 * <li>RF: 0x05</li>
	 * </ul>
	 *
	 * @param name KNX device name, used for human readable naming or device identification
	 * @param dd device descriptor
	 * @param device the device address, or the default individual address; if a device address is assigned, this
	 *        address shall be unique in the subnetwork the device resides
	 * @param link the KNX network link this device is attached to
	 * @throws KNXLinkClosedException if the network link is closed
	 * @throws KNXPropertyException on error setting KNX properties during device initialization
	 * @see #setServiceHandler(ProcessCommunicationService, ManagementService)
	 */
	protected BaseKnxDevice(final String name, final DeviceDescriptor dd, final IndividualAddress device,
		final KNXNetworkLink link) throws KNXLinkClosedException, KNXPropertyException
	{
		this(name, dd);
		init(device, link, null, null);
	}

	/**
	 * Creates a new KNX device.
	 * <p>
	 * The device address is either a configured subnetwork unique device address, or the default
	 * individual address if no address was assigned to the device yet. The default individual
	 * device address consists of a medium dependent default subnetwork address and the device
	 * address for unregistered devices. Unregistered devices are identified by using the device
	 * address 0xff, a value reserved for this purpose. The subnetwork address part describes the
	 * individual address' <i>area</i> and <i>line</i>. The default subnetwork address by medium is
	 * as follows, listed as <i>Medium</i>: <i>Subnetwork address</i>:
	 * <ul>
	 * <li>TP 1: 0x02</li>
	 * <li>PL 110: 0x04</li>
	 * <li>RF: 0x05</li>
	 * </ul>
	 *
	 * @param name KNX device name, used for human readable naming or device identification
	 * @param device the device address, or the default individual address; if a device address is
	 *        assigned, this address shall be unique in the subnetwork the device resides
	 * @param link the KNX network link this device is attached to
	 * @param process the device process communication service handler
	 * @param mgmt the device management service handler
	 * @throws KNXLinkClosedException if the network link is closed
	 * @throws KNXPropertyException on error setting KNX properties during device initialization
	 */
	public BaseKnxDevice(final String name, final IndividualAddress device,
		final KNXNetworkLink link, final ProcessCommunicationService process,
		final ManagementService mgmt) throws KNXLinkClosedException, KNXPropertyException
	{
		this(name, DeviceDescriptor.DD0.TYPE_5705);
		init(device, link, process, mgmt);
	}

	/**
	 * Creates a new KNX device using a {@link KnxDeviceServiceLogic} argument.
	 * <p>
	 * The device address is either a configured subnetwork unique device address, or the default
	 * individual address if no address was assigned to the device yet. The default individual
	 * device address consists of a medium dependent default subnetwork address and the device
	 * address for unregistered devices. Unregistered devices are identified by using the device
	 * address 0xff, a value reserved for this purpose. The subnetwork address part describes the
	 * individual address' <i>area</i> and <i>line</i>. The default subnetwork address by medium is
	 * as follows, listed as <i>Medium</i>: <i>Subnetwork address</i>:
	 * <ul>
	 * <li>TP 1: 0x02</li>
	 * <li>PL 110: 0x04</li>
	 * <li>RF: 0x05</li>
	 * </ul>
	 *
	 * @param name KNX device name, used for human readable naming or device identification
	 * @param device the device address, or the default individual address; if a device address is
	 *        assigned, this address shall be unique in the subnetwork the device resides
	 * @param link the KNX network link this device is attached to
	 * @param logic KNX device service logic
	 * @throws KNXLinkClosedException on closed network link
	 * @throws KNXPropertyException on error initializing the device properties
	 */
	public BaseKnxDevice(final String name, final IndividualAddress device, final KNXNetworkLink link,
		final KnxDeviceServiceLogic logic) throws KNXLinkClosedException, KNXPropertyException
	{
		this(name, device, link, logic, logic);
		logic.setDevice(this);
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
	protected final synchronized void setAddress(final IndividualAddress address)
	{
		if (address == null)
			throw new NullPointerException("device address cannot be null");
		self = address;
	}

	@Override
	public final synchronized IndividualAddress getAddress()
	{
		return self;
	}

	@Override
	public synchronized void setDeviceLink(final KNXNetworkLink link) throws KNXLinkClosedException
	{
		this.link = link;
		procNotifier = null;
		mgmtNotifier = null;
		if (link != null) {
			procNotifier = new ProcessServiceNotifier(this);
			mgmtNotifier = new ManagementServiceNotifier(this);
		}
	}

	@Override
	public final synchronized KNXNetworkLink getDeviceLink()
	{
		return link;
	}

	@Override
	public final InterfaceObjectServer getInterfaceObjectServer()
	{
		return ios;
	}

	/**
	 * @return the task executor providing the threads to run the process communication and
	 *         management services
	 */
	public ExecutorService taskExecutor()
	{
		return executor;
	}

	@Override
	public String toString()
	{
		return name + " " + self;
	}

	/**
	 * Sets the process communication service handler and management service handler for this
	 * device.
	 * <p>
	 * This method is to be called during device initialization by subtypes of BaseKnxDevice if the
	 * device uses service handlers, but did not set them during object creation using the supplied
	 * constructor.
	 *
	 * @param process the device handler for process communication, <code>null</code> if this device
	 *        does not use such handler
	 * @param mgmt the device handler for device management services, <code>null</code> if this
	 *        device does not use such handler
	 */
	protected synchronized final void setServiceHandler(final ProcessCommunicationService process,
		final ManagementService mgmt)
	{
		procNotifier.setServiceInterface(process);
		mgmtNotifier.setServiceInterface(mgmt);
	}

	void dispatch(final ServiceNotifier<?> sn, final EventObject e)
	{
		if (threadingPolicy == INCOMING_EVENTS_THREADED) {
			submitTask(() -> {
				try {
					final ServiceResult sr = sn.dispatch(e);
					// mgmt svc notifier always returns null, so don't check here for now
					if (sn instanceof ManagementServiceNotifier || sr != null)
						sn.response(e, sr);
				}
				finally {
					taskDone();
				}
			});
		}
		else {
			// the mgmt svc notifier does processing only in response, therefore it
			// always returns null here
			final ServiceResult sr = sn.dispatch(e);
			// ... because of this, allow null for mgmt svc notifier
			if (sn instanceof ManagementServiceNotifier || sr != null) {
				submitTask(() -> {
					try {
						sn.response(e, sr);
					}
					finally {
						taskDone();
					}
				});
			}
		}
	}

	DeviceDescriptor deviceDescriptor()
	{
		return dd;
	}

	Logger logger()
	{
		return logger;
	}

	private void init(final IndividualAddress device, final KNXNetworkLink link,
		final ProcessCommunicationService process, final ManagementService mgmt)
			throws KNXLinkClosedException, KNXPropertyException
	{
		// if we throw here for process == null or mgmt == null,
		// subclasses always have to supply handlers but cannot supply 'this' if the handlers are
		// implemented by the class
		//if (process == null || mgmt == null)
		//  throw new NullPointerException("handler missing");

		setAddress(device);
		setDeviceLink(link);
		setServiceHandler(process, mgmt);

		initKnxProperties();
		addDeviceInfo();
	}

	// taken from KNX server
	private void initKnxProperties() throws KNXPropertyException
	{
		// initialize interface device object properties
		setDeviceProperty(PID.MAX_APDULENGTH, new byte[] { 0, (byte) maxApduLength });
		final byte[] defDesc = new String("KNX Device").getBytes(Charset.forName("ISO-8859-1"));
		ios.setProperty(DEVICE_OBJECT, objectInstance, PID.DESCRIPTION, 1, defDesc.length, defDesc);

		final String[] sver = Settings.getLibraryVersion().split("\\.| |-");
		int last = 0;
		try {
			last = sver.length > 2 ? Integer.parseInt(sver[2]) : 0;
		}
		catch (final NumberFormatException e) {}
		final int ver = Integer.parseInt(sver[0]) << 12 | Integer.parseInt(sver[1]) << 6 | last;
		setDeviceProperty(PID.VERSION, new byte[] { (byte) (ver >>> 8), (byte) (ver & 0xff) });

		// revision counting is not aligned with library version for now
		setDeviceProperty(PID.FIRMWARE_REVISION, new byte[] { 1 });

		//
		// set properties used in device DIB for search response during discovery
		//
		// device status is not in programming mode
		setDeviceProperty(PID.PROGMODE, new byte[] { defDeviceStatus });
		setDeviceProperty(PID.SERIAL_NUMBER, defSerialNumber);
		// server KNX device address, since we don't know about routing at this time
		// address is always 0.0.0; might be updated later or by routing configuration
		final byte[] device = new IndividualAddress(0).toByteArray();

		// equal to PID.KNX_INDIVIDUAL_ADDRESS
		setDeviceProperty(PID.SUBNET_ADDRESS, new byte[] { device[0] });
		setDeviceProperty(PID.DEVICE_ADDRESS, new byte[] { device[1] });

		//
		// set properties used in manufacturer data DIB for discovery self description
		//
		setDeviceProperty(PID.MANUFACTURER_ID, fromWord(defMfrId));
		ios.setProperty(DEVICE_OBJECT, objectInstance, PID.MANUFACTURER_DATA, 1, defMfrData.length / 4, defMfrData);

		// set default medium to TP1 (Bit 1 set)
		ios.setProperty(InterfaceObject.CEMI_SERVER_OBJECT, objectInstance, PID.MEDIUM_TYPE, 1, 1, new byte[] { 0, 2 });

		// a device should set PID_MAX_APDULENGTH (Chapter 3/5/1 Resources)
		// don't confuse this with PID_MAX_APDU_LENGTH of the Router Object (PID = 58!!)
		ios.setDescription(new Description(0, 0, PID.MAX_APDULENGTH, 0, 0, true, 0, 10, 0, 0), true);
		setDeviceProperty(PID.MAX_APDULENGTH, fromWord(maxApduLength));
	}

	// property id to distinguish hardware types which are using the same
	// device descriptor mask version
	private static final int pidHardwareType = 78; // PDT Generic 6 bytes

	private void addDeviceInfo() throws KNXPropertyException
	{
		// in devices without PEI, value is 0
		// PEI type 1: Illegal adapter
		// PEI type 10, 12, 14 and 16: serial interface to application module
		// PEI type 10: protocol on top of FT1.2
		// PEI type 2, 4, 6, 8, 17: parallel I/O (17 = programmable I/O)
		final int peiType = 0; // unsigned char
		final int requiredPeiType = 0; // unsigned char
		final int manufacturerId = 0xffff; // unsigned word

		final int[] RunStateEnum = {
			0, // Halted or not loaded
			1, // Running
			2, // Ready for being executed
			3, // Terminated (app only starts again after restart/device reset)
			4, // Starting, required for apps with >2 s startup time
			5, // Shutting down
		};
		// TODO format is usage dependent: 1 byte read / 10 bytes write
		final int runState = RunStateEnum[1];
		final int firmwareRev = 3;

		// Physical PEI
		setDeviceProperty(PID.PEI_TYPE, fromByte(peiType));

		// application program object
		final int appProgamObject = InterfaceObject.APPLICATIONPROGRAM_OBJECT;
		ios.addInterfaceObject(appProgamObject);

		// Required PEI Type (Application Program Object)
		ios.setProperty(appProgamObject, objectInstance, PID.PEI_TYPE, 1, 1, fromByte(requiredPeiType));

		setDeviceProperty(PID.MANUFACTURER_ID, fromWord(manufacturerId));
		setDeviceProperty(PID.DEVICE_DESCRIPTOR, dd.toByteArray());

		// Programming Mode (memory address 0x60)
		final boolean programmingMode = false;
		setMemory(0x60, programmingMode ? 1 : 0);

		// Run State (Application Program Object)
		ios.setProperty(appProgamObject, objectInstance, PID.RUN_STATE_CONTROL, 1, 1, fromWord(runState));

		// Firmware Revision
		setDeviceProperty(PID.FIRMWARE_REVISION, fromByte(firmwareRev));

		// Hardware Type
		final byte[] hwType = new byte[6];
		setDeviceProperty(pidHardwareType, hwType);
		// validity check on mask and hardware type octets (AN059v3, AN089v3)
		final int maskVersion = ((DeviceDescriptor.DD0) dd).getMaskVersion();
		if ((maskVersion == 0x25 || maskVersion == 0x0705) && hwType[0] != 0) {
			logger.error("manufacturer-specific device identification of hardware type should be 0 for this mask!");
		}
		// Serial Number
		final byte[] sno = new byte[6]; // PDT Generic 10 bytes
		setDeviceProperty(PID.SERIAL_NUMBER, sno);
		// Order Info
		final byte[] orderInfo = new byte[10]; // PDT Generic 10 bytes
		setDeviceProperty(PID.ORDER_INFO, orderInfo);

		// Application ID (Application Program Object)
		final byte[] applicationVersion = new byte[5]; // PDT Generic 5 bytes
		ios.setProperty(appProgamObject, objectInstance, PID.PROGRAM_VERSION, 1, 1, applicationVersion);
	}

	private void setDeviceProperty(final int propertyId, final byte[] data) throws KNXPropertyException
	{
		ios.setProperty(DEVICE_OBJECT, objectInstance, propertyId, 1, 1, data);
	}

	private void submitTask(final Runnable task)
	{
		synchronized (tasks) {
			if (taskSubmitted)
				tasks.add(task);
			else {
				taskSubmitted = true;
				executor.submit(task);
			}
		}
	}

	private void taskDone()
	{
		synchronized (tasks) {
			if (tasks.isEmpty())
				taskSubmitted = false;
			else
				executor.submit(tasks.remove(0));
		}
	}

	private void setMemory(final int i, final int j)
	{
		// TODO Auto-generated method stub
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
