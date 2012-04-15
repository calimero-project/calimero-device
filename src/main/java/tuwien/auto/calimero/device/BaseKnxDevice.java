/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2011, 2012 B. Malinowsky

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

import java.nio.charset.Charset;
import java.util.EventObject;
import java.util.StringTokenizer;

import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.Settings;
import tuwien.auto.calimero.exception.KNXFormatException;
import tuwien.auto.calimero.exception.KNXIllegalArgumentException;
import tuwien.auto.calimero.link.KNXLinkClosedException;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.log.LogManager;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.mgmt.Description;
import tuwien.auto.calimero.mgmt.PropertyAccess;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.server.InterfaceObject;
import tuwien.auto.calimero.server.InterfaceObjectServer;
import tuwien.auto.calimero.server.KNXPropertyException;

/**
 * A skeleton implementation for a KNX device.
 * <p>
 * Notes for working with KNX devices: a KNX device can change its individual address. Therefore, do
 * not use the address as identifier.
 *
 * @author B. Malinowsky
 */
public class BaseKnxDevice implements KnxDevice
{
	// can be between 15 and 254 bytes (255 is Escape code for extended L_Data frames)
	private static int maxApduLength = 15;

	private final String name;
	private IndividualAddress self;

	//private ProcessCommunicator recv;

	private final LogService logger;

	// service event threading
	static final int INCOMING_EVENTS_THREADED = 1;
	static final int OUTGOING_EVENTS_THREADED = 2;
	private final int threadingPolicy;

	private TaskRunner taskRunner;

	private ProcessServiceNotifier procNotifier;
	private ManagementServiceNotifier mgmtNotifier;

	private InterfaceObjectServer ios = null;
	// The object instance determines which instance of an object type is
	// queried for properties. Always defaults to 1.
	private final int objectInstance = 1;

	private KNXNetworkLink link;
	private static final int devObject = InterfaceObject.DEVICE_OBJECT;

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

	BaseKnxDevice(final String name)
	{
		this.name = name;
		threadingPolicy = OUTGOING_EVENTS_THREADED;
		logger = LogManager.getManager().getLogService(name);
	}

	/**
	 * Creates a new KNX device.
	 * <p>
	 * The device individual address (see {@link IndividualAddress}) can either be a
	 * configured subnetwork unique device address, or the default individual address if
	 * no address was assigned to the device.<br>
	 * The default individual device address consists of a medium dependent default
	 * subnetwork address and the device address for unregistered devices. Unregistered
	 * devices are identified by using the device address 0xff, a value reserved for this
	 * purpose.<br>
	 * <br>
	 * The subnetwork address part describes the individual address
	 * <i>area</i> and <i>line</i>. The defined default subnetwork address by medium is,
	 * listed as "Medium" : "Subnetwork address":
	 * <ul>
	 * <li>TP 0: 0x01</li>
	 * <li>TP 1: 0x02</li>
	 * <li>PL 132: 0x03</li>
	 * <li>PL 110: 0x04</li>
	 * <li>RF: 0x05</li>
	 * </ul>
	 *
	 * @param device the device address, or the default individual address; if a device
	 *        address is assigned, this address shall be unique in the subnetwork the
	 *        device resides
	 * @param link the KNX network link this device is attached to
	 * @throws KNXLinkClosedException
	 * @throws KNXPropertyException
	 */
	public BaseKnxDevice(final String name, final IndividualAddress device,
		final KNXNetworkLink link) throws KNXLinkClosedException, KNXPropertyException
	{
		this(name);
		init(device, link, null, null);
	}

	/**
	 * Creates a new KNX device.
	 * <p>
	 * The device individual address (see {@link IndividualAddress}) can either be a
	 * configured subnetwork unique device address, or the default individual address if
	 * no address was assigned to the device.<br>
	 * The default individual device address consists of a medium dependent default
	 * subnetwork address and the device address for unregistered devices. Unregistered
	 * devices are identified by using the device address 0xff, a value reserved for this
	 * purpose.<br>
	 * <br>
	 * The subnetwork address part describes the individual address
	 * <i>area</i> and <i>line</i>. The defined default subnetwork address by medium is,
	 * listed as "Medium" : "Subnetwork address":
	 * <ul>
	 * <li>TP 0: 0x01</li>
	 * <li>TP 1: 0x02</li>
	 * <li>PL 132: 0x03</li>
	 * <li>PL 110: 0x04</li>
	 * <li>RF: 0x05</li>
	 * </ul>
	 *
	 * @param device the device address, or the default individual address; if a device
	 *        address is assigned, this address shall be unique in the subnetwork the
	 *        device resides
	 * @param link the KNX network link this device is attached to
	 * @param process the device process communication service handler
	 * @param mgmt the device management service handler
	 * @throws KNXLinkClosedException
	 * @throws KNXPropertyException
	 */
	public BaseKnxDevice(final IndividualAddress device, final KNXNetworkLink link,
		final ProcessCommunicationService process, final ManagementService mgmt)
		throws KNXLinkClosedException, KNXPropertyException
	{
		this("KNX device");
		init(device, link, process, mgmt);
	}

	/**
	 * Assigns a new KNX individual address to this device.
	 * <p>
	 * This method set the new address, and does <i>not</i> perform any other management
	 * or configuration tasks, e.g., ensuring a subnetwork unique device address, or
	 * publish the new address on the network.
	 *
	 * @param address the new device address
	 */
	protected final synchronized void setAddress(final IndividualAddress address)
	{
		if (address == null)
			throw new NullPointerException("device address cannot be null");
		self = address;
	}

	/* (non-Javadoc)
	 * @see tuwien.auto.calimero.device.KnxDevice#getAddress()
	 */
	public final synchronized IndividualAddress getAddress()
	{
		return self;
	}

	/**
	 * @return the service thread currently set for this device, or a worker thread that should be
	 *         used to work on a task
	 */
	public TaskRunner getServiceThread()
	{
		return taskRunner;
	}

	/* (non-Javadoc)
	 * @see tuwien.auto.calimero.device.KnxDevice#setDeviceLink(tuwien.auto.calimero.link.KNXNetworkLink)
	 */
	public synchronized void setDeviceLink(final KNXNetworkLink link) throws KNXLinkClosedException
	{
		this.link = link;
		procNotifier = null;
		mgmtNotifier = null;
		if (link != null) {
			procNotifier = new ProcessServiceNotifier(this, link);
			mgmtNotifier = new ManagementServiceNotifier(this, link);
		}
	}

	/* (non-Javadoc)
	 * @see tuwien.auto.calimero.device.KnxDevice#getDeviceLink()
	 */
	public final synchronized KNXNetworkLink getDeviceLink()
	{
		return link;
	}

	/* (non-Javadoc)
	 * @see tuwien.auto.calimero.device.KnxDevice#getInterfaceObjectServer()
	 */
	public final InterfaceObjectServer getInterfaceObjectServer()
	{
		return ios;
	}

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
	 * @param process the device handler for process communication, <code>null</code> if this
	 *        device does not use such handler
	 * @param mgmt the device handler for device management services, <code>null</code> if
	 *        this device does not use such handler
	 */
	protected synchronized final void setServiceHandler(final ProcessCommunicationService process,
		final ManagementService mgmt)
	{
		procNotifier.setServiceInterface(process);
		mgmtNotifier.setServiceInterface(mgmt);
	}

	void dispatch(final ServiceNotifier sn, final EventObject e)
	{
		if (threadingPolicy == INCOMING_EVENTS_THREADED) {
			runTask(new Runnable()
			{
				public void run()
				{
					final ServiceResult sr = sn.dispatch(e);
					// mgmt svc notifier always returns null, so don't check here for now
					//if (sr != null)
						sn.response(e, sr);
				}
			});
		}
		else {
			// the mgmt svc notifier does processing only in response, therefore it
			// always returns null here
			final ServiceResult sr = sn.dispatch(e);
			// ... because of this,  allow null for mgmt svc notifier
			if (sn instanceof ManagementServiceNotifier || sr != null) {
				runTask(new Runnable()
				{
					public void run()
					{
						sn.response(e, sr);
					};
				});
			}
		}
	}

	private void init(final IndividualAddress device, final KNXNetworkLink link,
		final ProcessCommunicationService process, final ManagementService mgmt)
		throws KNXLinkClosedException, KNXPropertyException
	{
		// if we throw here for processService == null or mgmtService == null,
		// subclasses always have to supply handlers but cannot supply 'this' if the handlers are
		// implemented by the class
		//if (processService == null || mgmtService == null)
		//  throw new NullPointerException("handler missing");

		setAddress(device);
		setDeviceLink(link);
		setServiceHandler(process, mgmt);

		initKnxProperties();
		addDeviceInfo();

		taskRunner = new TaskRunner();
		taskRunner.start();
	}

	// taken from KNX server
	private void initKnxProperties() throws KNXPropertyException
	{
		if (ios == null) {
			try {
				ios = new InterfaceObjectServer(false);
			}
			catch (final KNXFormatException e) {
				throw new KNXIllegalArgumentException("cannot create interface object server", e);
			}
		}

		// initialize interface device object properties
		ios.setProperty(devObject, objectInstance, PID.MAX_APDULENGTH, 1, 1, new byte[] { 0,
			(byte) maxApduLength });
		final byte[] defDesc = new String("KNX Device").getBytes(Charset.forName("ISO-8859-1"));
		ios.setProperty(devObject, objectInstance, PID.DESCRIPTION, 1, defDesc.length, defDesc);

		final String[] sver = split(Settings.getLibraryVersion(), ". -");
		int last = 0;
		try {
			last = sver.length > 2 ? Integer.parseInt(sver[2]) : 0;
		}
		catch (final NumberFormatException e) {}
		final int ver = Integer.parseInt(sver[0]) << 12 | Integer.parseInt(sver[1]) << 6 | last;
		ios.setProperty(devObject, objectInstance, PID.VERSION, 1, 1, new byte[] {
			(byte) (ver >>> 8), (byte) (ver & 0xff) });

		// revision counting is not aligned with library version for now
		ios.setProperty(devObject, objectInstance, PID.FIRMWARE_REVISION, 1, 1, new byte[] { 1 });

		//
		// set properties used in device DIB for search response during discovery
		//
		// device status is not in programming mode
		ios.setProperty(devObject, objectInstance, PID.PROGMODE, 1, 1,
				new byte[] { defDeviceStatus });
		ios.setProperty(devObject, objectInstance, PID.SERIAL_NUMBER, 1, 1, defSerialNumber);
		// server KNX device address, since we don't know about routing at this time
		// address is always 0.0.0; might be updated later or by routing configuration
		final byte[] device = new IndividualAddress(0).toByteArray();

		// equal to PID.KNX_INDIVIDUAL_ADDRESS
		ios.setProperty(devObject, objectInstance, PID.SUBNET_ADDRESS, 1, 1,
				new byte[] { device[0] });
		ios.setProperty(devObject, objectInstance, PID.DEVICE_ADDRESS, 1, 1,
				new byte[] { device[1] });

		//
		// set properties used in manufacturer data DIB for discovery self description
		//
		ios.setProperty(devObject, objectInstance, PID.MANUFACTURER_ID, 1, 1, fromWord(defMfrId));
		ios.setProperty(devObject, objectInstance, PID.MANUFACTURER_DATA, 1, defMfrData.length / 4,
				defMfrData);

		// set default medium to TP1 (Bit 1 set)
		ios.setProperty(InterfaceObject.CEMI_SERVER_OBJECT, objectInstance, PID.MEDIUM_TYPE, 1, 1,
				new byte[] { 0, 2 });

		// a device should set PID_MAX_APDULENGTH (Chapter 3/5/1 Resources)
		// don't confuse this with PID_MAX_APDU_LENGTH of the Router Object (PID = 58!!)
		ios.setDescription(new Description(0, 0, PID.MAX_APDULENGTH, 0, 0, true, 0, 10, 0, 0), true);
		ios.setProperty(devObject, objectInstance, PID.MAX_APDULENGTH, 1, 1,
				fromWord(maxApduLength));
	}

	// property id to distinguish hardware types which are using the same
	// device descriptor mask version
	private static final int pidHardwareType = 78; // PDT Generic 6 bytes

	private void addDeviceInfo() throws KNXPropertyException
	{
		final int appProgamObject = InterfaceObject.APPLICATIONPROGRAM_OBJECT;

		// in devices without PEI, value is 0
		// PEI type 1: Illegal adapter
		// PEI type 10, 12, 14 and 16: serial interface to application module
		// PEI type 10: protocol on top of FT1.2
		// PEI type 2, 4, 6, 8, 17: parallel I/O (17 = programmable I/O)
		final int peiType = 0; // unsigned char
		final int requiredPeiType = 0; // unsigned char
		final int manufacturerId = 0xffff; // unsigned word

		final boolean programmingMode = false;

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
		ios.setProperty(devObject, objectInstance, PropertyAccess.PID.PEI_TYPE, 1, 1,
				fromByte(peiType));

		// application program object
		ios.addInterfaceObject(InterfaceObject.APPLICATIONPROGRAM_OBJECT);

		// Required PEI Type (Application Program Object)
		ios.setProperty(appProgamObject, objectInstance, PropertyAccess.PID.PEI_TYPE, 1, 1,
				fromByte(requiredPeiType));

		// Manufacturer ID (Device Object)
		ios.setProperty(devObject, objectInstance, PropertyAccess.PID.MANUFACTURER_ID, 1, 1,
				fromWord(manufacturerId));

		// set device descriptor information
		// Device Descriptor Type 0 is 2 bytes:
		//        Mask Type (8 bit)                    Firmware Version (8 bit)
		// | Medium Type MMMM | Firmware Type FFFF | Version VVVV | Subcode SSSS |

		// set mask to something arbitrary
		//final int maskVersion = 0x0013; // TP1 BCU1 System 1
		//final int maskVersion = 0x0021; // TP1 BCU2 System 2
		final int maskVersion = 0x0025; // TP1 BCU2 System 2
		//final int maskVersion = 0x091A; // IP/TP1 KNXnet/IP router
		//final int maskVersion = 0x0705; // TP1 BIM M112

		// TODO set mask info
		//ios.setProperty(d, 0);

		// Programming Mode (memory address 0x60)
		setMemory(0x60, programmingMode ? 1 : 0);

		// Run State (Application Program Object)
		ios.setProperty(appProgamObject, objectInstance,
				PropertyAccess.PID.RUN_STATE_CONTROL, 1, 1, fromWord(runState));

		// Firmware Revision
		ios.setProperty(devObject, objectInstance,
				PropertyAccess.PID.FIRMWARE_REVISION, 1, 1, fromWord(firmwareRev));

		// Hardware Type
		final byte[] hwType = new byte[6];
		ios.setProperty(devObject, pidHardwareType, 1, 1, hwType);
		// validity check on mask and hardware type octets
		// AN059v3, AN089v3
		if ((maskVersion == 0x25 || maskVersion == 0x0705) && hwType[0] != 0) {
			System.err.println("manufacturer-specific device identification of hardware type "
					+ "should be 0 for this mask!");
		}
		// Serial Number
		final byte[] sno = new byte[6]; // PDT Generic 10 bytes
		ios.setProperty(devObject, PropertyAccess.PID.SERIAL_NUMBER, 1, 1, sno);
		// Order Info
		final byte[] orderInfo = new byte[10]; // PDT Generic 10 bytes
		ios.setProperty(devObject, PropertyAccess.PID.ORDER_INFO, 1, 1, orderInfo);

		// Application ID (Application Program Object)
		final byte[] applicationVersion = new byte[5]; // PDT Generic 5 bytes
		ios.setProperty(appProgamObject, objectInstance, PropertyAccess.PID.PROGRAM_VERSION, 1, 1,
				applicationVersion);
	}

	private void runTask(final Runnable task)
	{
		final TaskRunner t = getServiceThread();
		t.runTask(task);
	}

	private void setMemory(final int i, final int j)
	{
		// TODO Auto-generated method stub
	}

	private static String[] split(final String text, final String delim)
	{
		final StringTokenizer st = new StringTokenizer(text, delim);
		final String[] tokens = new String[st.countTokens()];
		for (int i = 0; i < tokens.length; ++i)
			tokens[i] = st.nextToken();
		return tokens;
	}

	private static byte[] fromWord(final int word)
	{
		return new byte[] { (byte) (word >> 8), (byte) word };
	}

	private static byte[] fromByte(final int uchar)
	{
		return new byte[] { (byte) uchar };
	}

	LogService getLogger()
	{
		return logger;
	}
}
