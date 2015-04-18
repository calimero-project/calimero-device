/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2012, 2015 B. Malinowsky

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

import java.util.EventObject;

import org.slf4j.Logger;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.DetachEvent;
import tuwien.auto.calimero.FrameEvent;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.Priority;
import tuwien.auto.calimero.cemi.CEMILData;
import tuwien.auto.calimero.exception.KNXTimeoutException;
import tuwien.auto.calimero.link.KNXLinkClosedException;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.mgmt.Description;
import tuwien.auto.calimero.mgmt.Destination;
import tuwien.auto.calimero.mgmt.KNXDisconnectException;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.mgmt.TransportLayer;
import tuwien.auto.calimero.mgmt.TransportLayerImpl;
import tuwien.auto.calimero.mgmt.TransportListener;
import tuwien.auto.calimero.server.InterfaceObject;
import tuwien.auto.calimero.server.KNXPropertyException;

/**
 * Listens to TL notifications, dispatches them to the appropriate management services, and answers
 * back to the sender using the service results.
 * <p>
 *
 * @author B. Malinowsky
 */
final class ManagementServiceNotifier implements TransportListener, ServiceNotifier
{
	// service IDs copied over from management client
	private static final int ADC_READ = 0x0180;
	private static final int ADC_RESPONSE = 0x01C0;

	private static final int AUTHORIZE_READ = 0x03D1;
	private static final int AUTHORIZE_RESPONSE = 0x03D2;

	private static final int DOA_WRITE = 0x3E0;
	private static final int DOA_READ = 0x3E1;
	private static final int DOA_RESPONSE = 0x3E2;
	private static final int DOA_SELECTIVE_READ = 0x3E3;

	private static final int IND_ADDR_READ = 0x0100;
	private static final int IND_ADDR_RESPONSE = 0x0140;
	private static final int IND_ADDR_WRITE = 0xC0;

	private static final int IND_ADDR_SN_READ = 0x03DC;
	private static final int IND_ADDR_SN_RESPONSE = 0x03DD;
	private static final int IND_ADDR_SN_WRITE = 0x03DE;

	private static final int DEVICE_DESC_READ = 0x300;
	private static final int DEVICE_DESC_RESPONSE = 0x340;

	private static final int KEY_WRITE = 0x03D3;
	private static final int KEY_RESPONSE = 0x03D4;

	private static final int MEMORY_READ = 0x0200;
	private static final int MEMORY_RESPONSE = 0x0240;
	private static final int MEMORY_WRITE = 0x0280;

	private static final int PROPERTY_DESC_READ = 0x03D8;
	private static final int PROPERTY_DESC_RESPONSE = 0x03D9;

	private static final int PROPERTY_READ = 0x03D5;
	private static final int PROPERTY_RESPONSE = 0x03D6;
	private static final int PROPERTY_WRITE = 0x03D7;

	private static final int RESTART = 0x0380;


	private static final int defaultMaxApduLength = 15;
	private boolean missingApduLength = false;

	private final BaseKnxDevice device;
	private final TransportLayer tl;
	private ManagementService mgmtSvc;

	private final Logger logger;

	private final int lengthDoA;

	// pre-condition: device != null, link != null
	ManagementServiceNotifier(final BaseKnxDevice device)
		throws KNXLinkClosedException
	{
		this.device = device;
		tl = new TransportLayerImpl(device.getDeviceLink(), true);
		tl.addTransportListener(this);
		logger = device.getLogger();

		final int medium = device.getDeviceLink().getKNXMedium().getMedium();
		if (medium == KNXMediumSettings.MEDIUM_PL110)
			lengthDoA = 2;
		else if (medium == KNXMediumSettings.MEDIUM_RF)
			lengthDoA = 6;
		else
			lengthDoA = 0;
	}

	public void broadcast(final FrameEvent e)
	{
		dispatchAndRespond(e);
	}

	public void dataConnected(final FrameEvent e)
	{
		dispatchAndRespond(e);
	}

	public void dataIndividual(final FrameEvent e)
	{
		dispatchAndRespond(e);
	}

	public void disconnected(final Destination d)
	{
		d.destroy();
	}

	public void group(final FrameEvent e)
	{}

	public void detached(final DetachEvent e)
	{}

	public void linkClosed(final CloseEvent e)
	{
		logger.info("attached link was closed");
	}

	public ServiceResult dispatch(final EventObject e)
	{
		// everything is done in response
		return null;
	}

	public void response(final EventObject e, final ServiceResult sr)
	{
		// since our service code is not split up in request/response, just do everything here
		final FrameEvent fe = (FrameEvent) e;
		final byte[] tpdu = fe.getFrame().getPayload();
		final int svc = DataUnitBuilder.getAPDUService(tpdu);
		final byte[] asdu = DataUnitBuilder.extractASDU(tpdu);
		final CEMILData cemi = (CEMILData) fe.getFrame();
		final IndividualAddress sender = cemi.getSource();

		if (tpdu.length > getMaxApduLength()) {
			logger.error(sender + "->" + cemi.getDestination() + " "
					+ DataUnitBuilder.decode(tpdu, cemi.getDestination())
					+ " exceeds max. allowed APDU length of " + getMaxApduLength() + " - ignore");
			return;
		}

		final TransportLayerImpl impl = (TransportLayerImpl) tl;
		Destination d = impl.getDestination(sender);
		// TODO actually this check is for CL mode and should be made in transport layer
		if (d == null)
			d = impl.createDestination(sender, false);

		try {
			dispatchToService(svc, asdu, d);
		}
		catch (final RuntimeException rte) {
			logger.error("executing service " + DataUnitBuilder.decodeAPCI(svc), rte);
			throw rte;
		}
	}

	public void setServiceInterface(final Object svcIf)
	{
		mgmtSvc = (ManagementService) svcIf;
	}

	private void dispatchAndRespond(final FrameEvent e)
	{
		device.dispatch(this, e);
	}

	private void dispatchToService(final int svc, final byte[] data, final Destination respondTo)
	{
		logger.trace(DataUnitBuilder.decodeAPCI(svc));
		if (svc == MEMORY_READ)
			onMemoryRead(respondTo, data);
		else if (svc == MEMORY_WRITE)
			onMemoryWrite(respondTo, data);
		else if (svc == PROPERTY_DESC_READ)
			onPropDescRead(respondTo, data);
		else if (svc == PROPERTY_READ)
			onPropertyRead(respondTo, data);
		else if (svc == PROPERTY_WRITE)
			onPropertyWrite(respondTo, data);
		else if (svc == DEVICE_DESC_READ)
			onDeviceDescRead(respondTo, data);
		else if (svc == ADC_READ)
			onAdcRead(respondTo, data);
		else if (svc == AUTHORIZE_READ)
			onAuthorize(respondTo, data);
		else if (svc == IND_ADDR_READ)
			onIndAddrRead(respondTo, data);
		else if (svc == IND_ADDR_WRITE)
			onIndAddrWrite(respondTo, data);
		else if (svc == IND_ADDR_SN_READ)
			onIndAddrSnRead(respondTo, data);
		else if (svc== IND_ADDR_SN_WRITE)
			onIndAddrSnWrite(respondTo, data);
		else if (svc == DOA_READ)
			onDoARead(respondTo, data);
		else if (svc == DOA_SELECTIVE_READ)
			onDoASelectiveRead(respondTo, data);
		else if (svc == DOA_WRITE)
			onDoAWrite(respondTo, data);
		else if (svc == KEY_WRITE)
			onKeyWrite(respondTo, data);
		else if (svc== RESTART)
			onRestart(respondTo, data);
		else
			onManagement(svc, respondTo, data);
	}

	private void onRestart(final Destination respondTo, final byte[] data)
	{
		if (!verifyLength(data.length, 1, 3, "restart"))
			return;

		// bits 1 to 4 in frame byte 7 (first byte ASDU) shall be 0; if not,
		// we have to ignore the service without any response
		final int reserved = data[0] & 0x1e;
		if (reserved != 0)
			return;

		final boolean masterReset = (data[0] & 0x01) == 1;
		final int eraseCode = masterReset ? data[1] & 0xff : 0;
		final int channel = masterReset ? data[2] & 0xff : 0;
		// a basic restart does not have any response,
		// a master reset returns an error code and process time
		final ServiceResult sr = mgmtSvc.restart(masterReset, eraseCode, channel);
		if (ignoreOrSchedule(sr))
			return;

		final byte[] res = sr.getResult();
		final byte[] asdu = new byte[4];
		asdu[0] = (1 << 5) | 1; // set response bit and master reset bit
		asdu[1] = res[0];
		asdu[2] = res[1];
		asdu[3] = res[2];
		final byte[] apdu = DataUnitBuilder.createLengthOptimizedAPDU(RESTART, asdu);
		send(respondTo, apdu, sr.getPriority());
	}

	// p2p connection-oriented mode
	private void onKeyWrite(final Destination respondTo, final byte[] data)
	{
		if (!verifyLength(data.length, 5, 5, "key write (access level)"))
			return;
		final int level = data[0] & 0xff;

		final byte[] key = DataUnitBuilder.copyOfRange(data, 1, 5);
		// if key equals 0xFFFFFFFF, the key of the level shall be reset
		// current access level has to be equal or less to level requested in this write
		// if not, keyWrite shall return 0xff
		// result is one byte containing the set level
		final ServiceResult sr = mgmtSvc.keyWrite(level, key);
		if (ignoreOrSchedule(sr))
			return;

		final byte[] asdu = sr.getResult();
		final byte[] apdu = DataUnitBuilder.createAPDU(KEY_RESPONSE, asdu);
		send(respondTo, apdu, sr.getPriority());
	}

	private void onIndAddrSnWrite(final Destination respondTo, final byte[] data)
	{
		if (!verifyLength(data.length, 12, 12, "individual address SN write"))
			return;
		final byte[] sn = DataUnitBuilder.copyOfRange(data, 0, 6);
		final byte[] addr = DataUnitBuilder.copyOfRange(data, 6, 8);
		final byte[] reserved = DataUnitBuilder.copyOfRange(data, 8, 12);
		// safety check that reserved area is zeroed out
		// we don't bail, since its not required by the spec
		for (int i = 0; i < reserved.length; i++) {
			final byte b = reserved[i];
			if (b != 0) {
				logger.warn("byte " + (16 + i) + " not 0 (reserved area)");
			}
		}
		final IndividualAddress ia = new IndividualAddress(addr);

		// this service does not have a response
		/*final ServiceResult sr =*/ mgmtSvc.writeAddressSerial(sn, ia);
	}

	private void onIndAddrSnRead(final Destination respondTo, final byte[] data)
	{
		if (!verifyLength(data.length, 6, 6, "individual address SN read"))
			return;

		final byte[] sn = DataUnitBuilder.copyOfRange(data, 0, 6);
		final ServiceResult sr = mgmtSvc.readAddressSerial(sn);
		if (ignoreOrSchedule(sr))
			return;

		// we don't need any result
		//final byte[] res = sr.getResult();
		// [serial no, DOA, 2 bytes reserved]
		final byte[] asdu = new byte[6 + 2 + 2];
		for (int i = 0; i < sn.length; i++) {
			final byte b = sn[i];
			asdu[i] = b;
		}
		final byte[] apdu = DataUnitBuilder.createAPDU(IND_ADDR_SN_RESPONSE, asdu);
		// priority is always system
		sendBroadcast(false, apdu, Priority.SYSTEM);
	}

	private void onIndAddrWrite(final Destination respondTo, final byte[] data)
	{
		if (!verifyLength(data.length, 2, 2, "individual address write"))
			return;

		final byte[] addr = DataUnitBuilder.copyOfRange(data, 0, 2);
		final IndividualAddress ia = new IndividualAddress(addr);
		// a device shall only set its address if in programming mode
		// this service does not have a response
		/*final ServiceResult sr =*/ mgmtSvc.writeAddress(ia);
	}

	private void onIndAddrRead(final Destination respondTo, final byte[] data)
	{
		if (!verifyLength(data.length, 1, 1, "individual address read"))
			return;

		// only a device in programming mode shall respond to this service
		final ServiceResult sr = mgmtSvc.readAddress();
		if (ignoreOrSchedule(sr))
			return;

		final byte[] asdu = new byte[0];
		final byte[] apdu = DataUnitBuilder.createAPDU(IND_ADDR_RESPONSE, asdu);
		send(respondTo, apdu, sr.getPriority());
	}

	private void onDoARead(final Destination respondTo, final byte[] data)
	{
		if (!verifyLength(data.length, 0, 0, "domain address read"))
			return;

		final ServiceResult sr = mgmtSvc.readDomainAddress();
		sendDoAresponse(respondTo, sr);
	}

	private void onDoASelectiveRead(final Destination respondTo, final byte[] data)
	{
		// selective read service is only defined for RF (domain length 2)
		if (!verifyLength(data.length, 5, 5, "domain address selective read"))
			return;
		final byte[] domain = DataUnitBuilder.copyOfRange(data, 0, 2);
		final IndividualAddress ia = new IndividualAddress(DataUnitBuilder.copyOfRange(data, 2, 4));
		final int range = data[4];

		final ServiceResult sr = mgmtSvc.readDomainAddress(domain, ia, range);
		sendDoAresponse(respondTo, sr);
	}

	private void sendDoAresponse(final Destination respondTo, final ServiceResult sr)
	{
		if (ignoreOrSchedule(sr))
			return;

		final byte[] domain = sr.getResult();
		if (domain.length != lengthDoA) {
			logger.error("length of domain address is " + domain.length + " bytes, should be "
					+ lengthDoA + " - ignore");
			return;
		}
		final byte[] apdu = DataUnitBuilder.createAPDU(DOA_RESPONSE, domain);
		send(respondTo, apdu, sr.getPriority());
	}

	private void onDoAWrite(final Destination respondTo, final byte[] data)
	{
		if (!verifyLength(data.length, lengthDoA, lengthDoA, "domain address write"))
			return;
		final byte[] domain = DataUnitBuilder.copyOfRange(data, 0, lengthDoA);
		/*final ServiceResult sr =*/ mgmtSvc.writeDomainAddress(domain);
	}

	// p2p connection-oriented mode
	private void onAuthorize(final Destination respondTo, final byte[] data)
	{
		if (!verifyLength(data.length, 5, 5, "authorize request"))
			return;
		final int reserved = data[0] & 0xff;

		if (reserved != 0) {
			logger.warn("first byte in authorize request not zero");
			return;
		}
		final byte[] key = DataUnitBuilder.copyOfRange(data, 1, 5);
		final ServiceResult sr = mgmtSvc.authorize(key);
		if (ignoreOrSchedule(sr))
			return;

		final byte[] asdu = sr.getResult();
		final byte[] apdu = DataUnitBuilder.createAPDU(AUTHORIZE_RESPONSE, asdu);
		send(respondTo, apdu, sr.getPriority());
	}

	// p2p connection-oriented mode
	private void onAdcRead(final Destination respondTo, final byte[] data)
	{
		if (!verifyLength(data.length, 2, 2, "AD converter read"))
			return;
		final int channel = data[0] & 0x3f;
		// number of consecutive reads of AD converter
		final int reads = data[1] & 0xff;
		// the returned structure is [channel, read count, value high, value low]
		final ServiceResult sr = mgmtSvc.readADC(channel, reads);
		if (ignoreOrSchedule(sr))
			return;

		final byte[] asdu = sr.getResult();
		final byte[] apdu = DataUnitBuilder.createLengthOptimizedAPDU(ADC_RESPONSE, asdu);
		send(respondTo, apdu, sr.getPriority());
	}

	private void onDeviceDescRead(final Destination d, final byte[] data)
	{
		if (!verifyLength(data.length, 1, 1, "device descriptor read"))
			return;
		final int type = data[0] & 0xff;
		// Descriptor type 0:
		// mask type (8 bit): Medium Type (4 bit), Firmware Type (4 bit)
		// firmware version (8 bit): version (4 bit), sub code (4 bit)

		// Descriptor type 1:
		// | application manufacturer (16 bit) | device type (16 bit) | version (8 bit) |
		// link mgmt service support (2 bit) | logical tag (LT) base value (6 bit) |
		// CI 1 (16 bit) | CI 2 (16 bit) | CI 3 (16 bit) | CI 4 (16 bit) |

		if (type != 0 && type != 2) {
			logger.warn("device descriptor read: unsupported type " + type);
			return;
		}
		final ServiceResult sr = mgmtSvc.readDescriptor(type);
		if (ignoreOrSchedule(sr))
			return;

		final byte[] asdu = sr.getResult();
		final byte[] apdu = DataUnitBuilder.createAPDU(DEVICE_DESC_RESPONSE, asdu);
		apdu[1] |= type;
		send(d, apdu, sr.getPriority());
	}

	private ServiceResult onPropertyRead(final Destination d, final byte[] data)
	{
		if (!verifyLength(data.length, 4, 4, "property-read"))
			return null;
		final int objIndex = data[0] & 0xff;
		final int pid = data[1] & 0xff;
		int elements = (data[2] & 0xff) >> 4;
		final int start = (data[2] & 0x0f) << 8 | (data[3] & 0xff);

		// to indicate an (illegal) access problem, or protected memory,
		// set number of elements 0, with no property values included
		final ServiceResult sr = mgmtSvc.readProperty(objIndex, pid, start, elements);
		if (sr == null || sr.getResult() == null)
			return sr;
		final byte[] res = sr.getResult();
		final byte[] asdu = new byte[4 + res.length];
		if (res.length == 0)
			elements = 0;
		asdu[0] = (byte) objIndex;
		asdu[1] = (byte) pid;
		asdu[2] = (byte) ((elements << 4) | ((start >>> 8) & 0x0f));
		asdu[3] = (byte) start;
		for (int i = 0; i < res.length; ++i)
			asdu[i + 4] = res[i];

		final byte[] apdu = DataUnitBuilder.createAPDU(PROPERTY_RESPONSE, asdu);
		send(d, apdu, sr.getPriority());
		return sr;
	}

	private ServiceResult onPropertyWrite(final Destination d, final byte[] data)
	{
		// the max ASDU upper length would be 254 - (2 bytes APCI)
		if (!verifyLength(data.length, 5, getMaxApduLength() - 2, "property-write"))
			return null;
		final int objIndex = data[0] & 0xff;
		final int pid = data[1] & 0xff;
		int elements = (data[2] & 0xff) >> 4;
		final int start = (data[2] & 0x0f) << 8 | (data[3] & 0xff);
		final byte[] propertyData = DataUnitBuilder.copyOfRange(data, 4, data.length);

		final ServiceResult sr = mgmtSvc.writeProperty(objIndex, pid, start,
			elements, propertyData);
		if (sr == null || sr.getResult() == null)
			return sr;
		final byte[] res = sr.getResult();

		// to indicate an (illegal) access problem, or protected memory,
		// set number of elements 0, with no property values included
		int written = res.length;
		if (res.length != propertyData.length) {
			elements = 0;
			written = 0;
		}
		final byte[] asdu = new byte[4 + written];
		asdu[0] = (byte) objIndex;
		asdu[1] = (byte) pid;
		asdu[2] = (byte) ((elements << 4) | ((start >>> 8) & 0x0f));
		asdu[3] = (byte) start;
		for (int i = 0; i < written; ++i)
			asdu[4 + i] = res[i];

		final byte[] apdu = DataUnitBuilder.createAPDU(PROPERTY_RESPONSE, asdu);
		send(d, apdu, sr.getPriority());
		return sr;
	}

	private ServiceResult onPropDescRead(final Destination d, final byte[] data)
	{
		if (!verifyLength(data.length, 3, 3, "property description read"))
			return null;
		final int objIndex = data[0] & 0xff;
		int pid = data[1] & 0xff;
		final int propIndex = data[2] & 0xff;

		final ServiceResult sr = mgmtSvc.readPropertyDescription(objIndex, pid, propIndex);
		// answer with non-existent property description on no result
		if (sr == null) {
			final byte[] asdu = new byte[7];
			final byte[] apdu = DataUnitBuilder.createAPDU(PROPERTY_DESC_RESPONSE, asdu);
			send(d, apdu, Priority.LOW);
			return sr;
		}
		if (ignoreOrSchedule(sr))
			return sr;

		final int typeDontCare = 0;
		final Description desc = new Description(typeDontCare, sr.getResult());
		// read back pid, because it is 0 when the propIndex was used
		pid = desc.getPID();
		final int index = desc.getPropIndex();
		int type = desc.isWriteEnabled() ? 0x80 : 0;
		type |= desc.getPDT();
		final int max = desc.getMaxElements();
		final int access = desc.getReadLevel() << 4 | desc.getWriteLevel();
		final byte[] asdu = new byte[/*7*/] { (byte) objIndex, (byte) pid, (byte) index,
			(byte) type, (byte) (max >>> 8), (byte) max, (byte) access };

		final byte[] apdu = DataUnitBuilder.createAPDU(PROPERTY_DESC_RESPONSE, asdu);
		send(d, apdu, sr.getPriority());
		return sr;
	}

	private ServiceResult onMemoryWrite(final Destination d, final byte[] data)
	{
		if (!verifyLength(data.length, 4, 66, "memory-write"))
			return null;

		// write between 1 and 63 bytes
		int bytes = data[0];
		final int address = ((data[1] & 0xff) << 8) | data[2] & 0xff;

		// the remote application layer shall ignore a memory-write.ind if
		// the value of the parameter number is greater than maximum APDU length – 3
		if (bytes > getMaxApduLength() - 3) {
			logger.error("memory-write too much data - ignore");
			return null;
		}

		final byte[] memory = DataUnitBuilder.copyOfRange(data, 3, data.length);
		if (memory.length != bytes)
			logger.warn("ill-formed memory write: number field = {} but memory length = {}",
					bytes, memory);
		else {
			final ServiceResult sr = mgmtSvc.writeMemory(address, memory);
			if (sr == null || sr.getResult() == null)
				return sr;
			final byte[] written = sr.getResult();
			// check for unreachable/illegal/protected memory access
			if (written.length == 0)
				bytes = 0;
			else if (written.length != bytes) {
				logger.warn("wrong implementation of memory-write?");
				bytes = 0;
			}
			// only respond if verify mode is active
			final boolean verifyByServer = mgmtSvc.isVerifyModeEnabled();
			if (verifyByServer) {
				final byte[] asdu = new byte[3 + bytes];
				asdu[0] = (byte) bytes;
				asdu[1] = (byte) (address >>> 8);
				asdu[2] = (byte) address;
				for (int i = 0; i < bytes; ++i)
					asdu[3 + i] = written[i];

				final byte[] apdu = DataUnitBuilder.createAPDU(MEMORY_RESPONSE, asdu);
				send(d, apdu, sr.getPriority());
			}
		}
		return null;
	}

	private ServiceResult onMemoryRead(final Destination d, final byte[] data)
	{
		if (!verifyLength(data.length, 3, 3, "memory-read"))
			return null;
		final int length = data[0];
		final int address = data[1] & 0xff << 8 | data[2] & 0xff;

		// requests with a length exceeding the maximum APDU size shall be
		// ignored by the application
		if (length > getMaxApduLength() - 3) {
			logger.warn("memory-read request length too long - ignored");
			return null;
		}
		final ServiceResult sr = mgmtSvc.readMemory(address, length);
		if (sr == null || sr.getResult() == null)
			return sr;

		final byte[] res = sr.getResult();
		// res null or length 0 indicate memory access problems, i.e.,
		// read protection, invalid address, partial read.
		int bytesRead = length;
		if (res == null || res.length != bytesRead)
			bytesRead = 0;

		final byte[] asdu = new byte[3 + bytesRead];
		asdu[0] = (byte) bytesRead;
		asdu[1] = (byte) (address >> 8);
		asdu[2] = (byte) address;
		for (int i = 0; i < bytesRead; ++i)
			asdu[3 + i] = res[i];

		final byte[] apdu = DataUnitBuilder.createLengthOptimizedAPDU(MEMORY_RESPONSE, asdu);
		send(d, apdu, sr.getPriority());
		return sr;
	}

	private ServiceResult onManagement(final int svcType, final Destination respondTo,
		final byte[] data)
	{
		final ServiceResult sr = mgmtSvc.management(svcType, data);
		return sr;
	}

	private boolean verifyLength(final int length, final int minExpected, final int maxExpected,
		final String svcType)
	{
		if (length < minExpected)
			logger.error(svcType + " SDU of length " + length + " too short, expected "
					+ minExpected);
		else if (length > maxExpected)
			logger.error(svcType + " SDU of length " + length + " too long, maximum " + maxExpected);
		return length >= minExpected && length <= maxExpected;
	}

	private boolean ignoreOrSchedule(final ServiceResult svc)
	{
		if (svc == null)
			return true;
		if (svc.getResult() != null)
			return false;
		svc.run();
		return true;
	}

	private void sendBroadcast(final boolean system, final byte[] apdu, final Priority p)
	{
		final String type = system ? "system" : "domain";
		logger.trace(this.device.getAddress() + "->[" + type + " broadcast]" + " respond with "
				+ DataUnitBuilder.toHex(apdu, " "));
		try {
				tl.broadcast(system, p, apdu);
		}
		catch (final KNXLinkClosedException e) {
			e.printStackTrace();
		}
		catch (final KNXTimeoutException e) {
			e.printStackTrace();
		}
	}

	private void send(final Destination respondTo, final byte[] apdu, final Priority p)
	{
		logger.trace(this.device.getAddress() + "->" + respondTo.getAddress() + " respond with "
				+ DataUnitBuilder.toHex(apdu, " "));
		try {
			if (respondTo.isConnectionOriented())
				tl.sendData(respondTo, p, apdu);
			else
				tl.sendData(respondTo.getAddress(), p, apdu);
		}
		catch (final KNXDisconnectException e) {
			e.printStackTrace();
		}
		catch (final KNXLinkClosedException e) {
			e.printStackTrace();
		}
		catch (final KNXTimeoutException e) {
			e.printStackTrace();
		}
	}

	private int getMaxApduLength()
	{
		try {
			final byte[] length = device.getInterfaceObjectServer().getProperty(
					InterfaceObject.DEVICE_OBJECT, PID.MAX_APDULENGTH, 1, 1);
			return toUnsigned(length);
		}
		catch (final KNXPropertyException e) {
			if (!missingApduLength) {
				missingApduLength = true;
				logger.error("device has no maximum APDU length set (PID.MAX_APDULENGTH), using "
						+ defaultMaxApduLength);
			}
			return defaultMaxApduLength;
		}
	}

	// for a max of (2^31)-1
	private static int toUnsigned(final byte[] data)
	{
		if (data.length == 2)
			return (data[0] & 0xff) << 8 | data[1] & 0xff;
		return (data[0] & 0xff) << 24 | (data[1] & 0xff) << 16 | (data[2] & 0xff) << 8 | data[3]
				& 0xff;
	}
};
