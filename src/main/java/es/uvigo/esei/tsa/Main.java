package es.uvigo.esei.tsa;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.zeroturnaround.zip.ZipUtil;

/**
 *
 * @author ribadas
 */
// ZIP https://github.com/zeroturnaround/zt-zip
// TSA request  https://stackoverflow.com/questions/8389664/java-implementation-of-time-stamp-protocol
public class Main {

    private final static Logger logger = Logger.getLogger(Main.class.getName());

    public final static void main(String[] args) {
        if (args.length == 0) {
            args = new String[]{"/tmp/kk"};
        }

        String source = args[0];
        String destination = source + ".zip";

        zipSource(source, destination);
        createTS(destination);
    }

    private static void zipSource(String source, String destination) {
        File sourceFile = new File(source);
        File destinationFile = new File(destination);
        if (sourceFile.isDirectory()) {
            ZipUtil.pack(sourceFile, destinationFile, true);
        } else {
            ZipUtil.packEntry(sourceFile, destinationFile);
        }
    }

    private static void createTS(String destination) {
        byte[] hash = computeSHA512(new File(destination));

        String ocspUrl = "https://freetsa.org/tsr";// otra TSA "http://time.certum.pl"; //del ejemplo "http://timestamping.edelweb.fr/service/tsp";       
        OutputStream out = null;
        HttpURLConnection con = null;

        try {

            TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
            //timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("1.3.6.1.4.1.51861.1.1")); 
//            TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA512, hash, BigInteger.valueOf(100));
            TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA512, hash);
            byte request[] = timeStampRequest.getEncoded();

            save(new File(destination + ".tsq"), request);

            URL url = new URL(ocspUrl);
            con = (HttpURLConnection) url.openConnection();
            con.setDoOutput(true);
            con.setDoInput(true);
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-type", "application/timestamp-query");
            con.setRequestProperty("Content-length", String.valueOf(request.length));
            out = con.getOutputStream();
            out.write(request);
            out.flush();

            if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
                throw new IOException("Received HTTP error: " + con.getResponseCode() + " - " + con.getResponseMessage());
            } else {
                logger.log(Level.INFO, "Response Code: ".concat(Integer.toString(con.getResponseCode())));
            }
            InputStream in = con.getInputStream();
            TimeStampResp resp = TimeStampResp.getInstance(new ASN1InputStream(in).readObject());
            TimeStampResponse response = new TimeStampResponse(resp);

            save(new File(destination + ".tsr"), response.getEncoded());
            printResponse(response);

            response.validate(timeStampRequest);

            logger.log(Level.INFO, "Status = {0}", response.getStatusString());

            if (response.getFailInfo() != null) {

                switch (response.getFailInfo().intValue()) {
                    case 0: {
                        logger.log(Level.INFO, "unrecognized or unsupported Algorithm Identifier");
                        return;
                    }

                    case 2: {
                        logger.log(Level.INFO, "transaction not permitted or supported");
                        return;
                    }

                    case 5: {
                        logger.log(Level.INFO, "the data submitted has the wrong format");
                        return;
                    }

                    case 14: {
                        logger.log(Level.INFO, "the TSA’s time source is not available");
                        return;
                    }

                    case 15: {
                        logger.log(Level.INFO, "the requested TSA policy is not supported by the TSA");
                        return;
                    }
                    case 16: {
                        logger.log(Level.INFO, "the requested extension is not supported by the TSA");
                        return;
                    }

                    case 17: {
                        logger.log(Level.INFO, "the additional information requested could not be understood or is not available");
                        return;
                    }

                    case 25: {
                        logger.log(Level.INFO, "the request cannot be handled due to system failure");
                        return;
                    }
                }
            }

            logger.log(Level.INFO, "Timestamp: {0}", response.getTimeStampToken().getTimeStampInfo().getGenTime());
            logger.log(Level.INFO, "TSA: {0}", response.getTimeStampToken().getTimeStampInfo().getTsa());
            logger.log(Level.INFO, "Serial number: {0}", response.getTimeStampToken().getTimeStampInfo().getSerialNumber());
            logger.log(Level.INFO, "Policy: {0}", response.getTimeStampToken().getTimeStampInfo().getPolicy());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] computeSHA512(File file) {
        try {
            Security.addProvider(new BouncyCastleProvider());

            MessageDigest hash = MessageDigest.getInstance("SHA-512", "BC");

            byte[] data = Files.readAllBytes(file.toPath());
            hash.update(data);
            return hash.digest();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null; // TODO
    }

    private static void save(File file, byte[] data) {
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(data);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }
        // TODO
    }

    private static void printResponse(TimeStampResponse response) {
        // TODO
    }
}
