module Network.Socks5.Lowlevel
    ( resolveToSockAddr
    , resolveToSockAddr6
    , socksListen
    -- * lowlevel types
    , module Network.Socks5.Wire
    , module Network.Socks5.Command
    ) where

import Network.Socket
import Network.BSD
import Network.Socks5.Command
import Network.Socks5.Wire
import Network.Socks5.Types
import qualified Data.ByteString.Char8 as BC

resolveToSockAddr :: SocksAddress -> IO SockAddr
resolveToSockAddr (SocksAddress sockHostAddr port) =
    case sockHostAddr of
        SocksAddrIPV4 ha       -> return $ SockAddrInet port ha
        SocksAddrIPV6 ha6      -> return $ SockAddrInet6 port 0 ha6 0
        SocksAddrDomainName bs -> do he <- getHostByName (BC.unpack bs)
                                     return $ SockAddrInet port (hostAddress he)

resolveToSockAddr6 :: SocksAddress -> IO SockAddr
resolveToSockAddr6 addr@(SocksAddress sockHostAddr port) =
    case sockHostAddr of
        SocksAddrIPV4 _         -> fail "Cannot connect using a IPv6 socket to a IPv4 address"
        SocksAddrIPV6 _         -> resolveToSockAddr addr
        SocksAddrDomainName bs  -> do
            let hints = defaultHints { addrFamily = AF_INET6, addrSocketType = Stream }
            info <- getAddrInfo (Just hints) (Just . BC.unpack $ bs) (Just (show port))
            return . addrAddress . head $ info
             

socksListen :: Socket -> IO SocksRequest
socksListen sock = do
    hello <- waitSerialized sock
    case getSocksHelloMethods hello of
        _ -> do sendSerialized sock (SocksHelloResponse SocksMethodNone)
                waitSerialized sock
