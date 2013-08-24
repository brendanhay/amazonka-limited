{-# LANGUAGE OverloadedStrings               #-}

{-# OPTIONS_GHC -fno-warn-missing-signatures #-}

-- Module      : Network.AWS.Internal
-- Copyright   : (c) 2013 Brendan Hay <brendan.g.hay@gmail.com>
-- License     : This Source Code Form is subject to the terms of
--               the Mozilla Public License, v. 2.0.
--               A copy of the MPL can be found in the LICENSE file or
--               you can obtain it at http://mozilla.org/MPL/2.0/.
-- Maintainer  : Brendan Hay <brendan.g.hay@gmail.com>
-- Stability   : experimental
-- Portability : non-portable (GHC extensions)

module Network.AWS.Internal
    (
    -- * Internal Modules
      module Network.AWS.Internal.Instances
    , module Network.AWS.Internal.Signing
    , module Network.AWS.Internal.String
    , module Network.AWS.Internal.Types

    -- * Convenience
    , module GHC.Generics
    , module Network.HTTP.QueryString.Pickle
    , module Text.XML.Expat.Pickle.Generic

    -- * XML Helpers
    , withNS
    , withRootNS
    ) where

import Data.Monoid
import GHC.Generics
import Network.AWS.Internal.Instances
import Network.AWS.Internal.Signing
import Network.AWS.Internal.String
import Network.AWS.Internal.Types
import Network.HTTP.QueryString.Pickle
import Text.XML.Expat.Pickle.Generic
import Data.ByteString                 (ByteString)

withNS ns = pu { root = namespace ns `fmap` (root pu) }
  where
    pu = genericXMLPickler defaultXMLOptions

withRootNS ns name = (genericXMLPickler defaultXMLOptions)
   { root = Just $ namespace ns name
   }

namespace :: ByteString -> ByteString -> ByteString
namespace ns name = name <> " xmlns=\"" <> ns <> "\""
