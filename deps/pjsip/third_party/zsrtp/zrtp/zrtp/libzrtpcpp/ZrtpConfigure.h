/*
  Copyright (C) 2009 - 2013 Werner Dittmann

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#ifndef _ZRTPCONFIGURE_H_
#define _ZRTPCONFIGURE_H_

/**
 * @file ZrtpConfigure.h
 * @brief The ZRTP configure functions
 * @ingroup GNU_ZRTP
 * @{
 */

#include <stdio.h>
#include <stdint.h>
#include <list>
#include <string>
#include <vector>
#include <string.h>

#include <libzrtpcpp/ZrtpCallback.h>

/**
 * This enumerations list all configurable algorithm types.
 */

enum AlgoTypes {
    Invalid = 0, HashAlgorithm = 1, CipherAlgorithm, PubKeyAlgorithm, SasType, AuthLength
};

typedef void(*encrypt_t)(uint8_t*, int32_t, uint8_t*, uint8_t*, int32_t);
typedef void(*decrypt_t)(uint8_t*, int32_t, uint8_t*, uint8_t*, int32_t);

/**
 * The algorithm enumration class.
 *
 * This simple class is just a container of an algorithm's name and
 * its associated algorithm type. We use this class together with the
 * EnumBase class to implement a Java-like enum class functionality
 * (not fully, but OK for our use case).
 *
 * An application shall use the get / check methods to retrieve information.
 */
class AlgorithmEnum {
public:
    /**
     * Create an AlgorithmEnum object.
     *
     * @param type
     *    Defines the algorithm type
     * @param name
     *    Set the names of the algorithm. The name is copied
     *    and the call may reuse the space.
     * @param klen
     *    The key length for this algorihm in byte, for example 16 or 32
     * @param ra
     *    A human readable short string that describes the algorihm.
     * @param en
     *    Pointer to the encryption function of this algorithn
     * @param de
     *    Pointer to the decryption funtions of this algorithm.
     * @param alId
     *    The algorithm id used by SRTP to identify an algorithm type, for
     *    example Skein, Sha1, Aes, ...
     *
     * @see AlgoTypes
     */
    AlgorithmEnum(const AlgoTypes type, const char* name, int32_t klen,
                  const char* ra, encrypt_t en, decrypt_t de, SrtpAlgorithms alId);

    /**
     * AlgorithmEnum destructor
     */
    ~AlgorithmEnum();

    /**
     * Get the algorihm's name
     *
     * @returns
     *    Algorithm's name as null terminated C-string. The
     *    application must not free this memory.
     */
    const char* getName();

    /**
     * Get the algorihm's readable name
     *
     * @returns
     *    Algorithm's readable name as null terminated C-string. The
     *    application must not free this memory.
     */
    const char* getReadable();

    /**
     * Get the algorihm's key length.
     *
     * @returns
     *    An integer definig the key length in bytes.
     */
    int getKeylen();

    /**
     * Get the algorihm's integer id.
     *
     * @returns
     *    An integer that defines the algorithm.
     */
    SrtpAlgorithms getAlgoId();
    /**
     * Get the algorihm's key length.
     *
     * @returns
     *    An integer definig the key length in bytes.
     */
    encrypt_t getEncrypt();

    /**
     * Get the algorihm's key length.
     *
     * @returns
     *    An integer definig the key length in bytes.
     */
    decrypt_t getDecrypt();

    /**
     * Get the algorithm type of this AlgorithmEnum object.
     *
     * @returns
     *     The algorithm type.
     *
     * @see AlgoTypes
     */
    AlgoTypes getAlgoType();

    /**
     * Check if this AlgorithmEnum object is valid
     *
     * @returns
     *    @c true if the object is valid, @c false otherwise
     */
    bool isValid();

private:
    AlgoTypes algoType;
    std::string algoName;
    int32_t   keyLen;
    std::string readable;
    encrypt_t encrypt;
    decrypt_t decrypt;
    SrtpAlgorithms   algoId;
};

/**
 * EnumBase provides methods to store and access algorithm enumerations of
 * a specific algorithm type.
 *
 * An application shall use the get / check methods to retrieve information
 * from the preset Algorithm Enumerations.
 *
 * @see AlgoTypes
 * @see zrtpHashes
 * @see zrtpSymCiphers
 * @see zrtpPubKeys
 * @see zrtpSasTypes
 * @see zrtpAuthLengths
 */
class __EXPORT EnumBase {
public:
    /**
     * Get an AlgorithmEnum by its name
     *
     * @param name
     *    The name of the AlgorithmEnum to search.
     * @returns
     *    The AlgorithmEnum if found or an invalid AlgorithmEnum if the name
     *    was not found
     */
    AlgorithmEnum& getByName(const char* name);

    /**
     * Return all names of all currently stored AlgorithmEnums
     *
     * @return
     *    A C++ std::list of C++ std::strings that contain the names.
     */
    std::list<std::string>* getAllNames();

    /**
     * Get the number of currently stored AlgorithmEnums
     *
     * @return
     *    The number of currently stored AlgorithmEnums
     */
    int getSize();

    /**
     * Get the AlgoTypes to which this EnumBase belongs.
     *
     * @return
     *     The AlgoTypes of this EnumBase.
     * @see AlgoTypes.
     */
    AlgoTypes getAlgoType();

    /**
     * Return the AlgorithmEnum by its ordinal number
     *
     * @param ord
     *     The ordinal number of the AlgorithmEnum.
     * @return
     *     The AlgorithmEnum if found, an invalid Algorithm otherwise.
     */
    AlgorithmEnum& getByOrdinal(int ord);

    /**
     * Get the ordinal number of an AlgorithmEnum
     *
     * @param algo
     *     Return toe ordinal numer of this AlgorithmEnum.
     *
     * @return
     *    Return the ordinal number of this AlgorithmEnum if found,
     *    -1 otherwise.
     */
    int getOrdinal(AlgorithmEnum& algo);

protected:
    EnumBase(AlgoTypes algo);
    ~EnumBase();
    void insert(const char* name);
    void insert(const char* name, int32_t klen,
                const char* ra, encrypt_t en, decrypt_t de, SrtpAlgorithms alId);

private:
    AlgoTypes algoType;
    std::vector <AlgorithmEnum* > algos;
};

/**
 * The enumaration subclasses that contain the supported algorithm enumerations.
 */
class __EXPORT HashEnum : public EnumBase {
public:
    HashEnum();
    ~HashEnum();
};

class __EXPORT SymCipherEnum : public EnumBase {
public:
    SymCipherEnum();
    ~SymCipherEnum();
};

class __EXPORT PubKeyEnum : public EnumBase {
public:
    PubKeyEnum();
    ~PubKeyEnum();
};

class __EXPORT SasTypeEnum : public EnumBase {
public:
    SasTypeEnum();
    ~SasTypeEnum();
};

class __EXPORT AuthLengthEnum : public EnumBase {
public:
    AuthLengthEnum();
    ~AuthLengthEnum();
};

extern __EXPORT HashEnum zrtpHashes;
extern __EXPORT SymCipherEnum zrtpSymCiphers;
extern __EXPORT PubKeyEnum zrtpPubKeys;
extern __EXPORT SasTypeEnum zrtpSasTypes;
extern __EXPORT AuthLengthEnum zrtpAuthLengths;

/**
 * ZRTP configuration data.
 *
 * This class contains data and functions to set ZRTP configuration data.
 * An application may use this class to set configuration information for
 * ZRTP. ZRTP uses this configuration information to announce various
 * algorithms via its Hello message. An application may use this class to
 * restrict or allow use of algorithms.
 *
 * The constructor does not set any algorithms, thus it is an empty
 * configuration. An application may use this empty configuration and
 * hand it over to ZRTP. In this case ZRTP does not announce any algorithms
 * in its Hello message and uses mandatory algorithms only.
 *
 * An application can configure implemented algorithms only.
 */
class __EXPORT ZrtpConfigure {
public:
    ZrtpConfigure();         /* Creates Configuration data */
    ~ZrtpConfigure();

    /**
     * Define the algorithm selection policies.
     */
    typedef enum _policies {
        Standard = 1,
        PreferNonNist = 2
    } Policy;

    /**
     * Set the maximum number of algorithms per algorithm type that an application can
     * configure.
     */
    static const int maxNoOfAlgos = 7;
    /**
     * Convenience function that sets a pre-defined standard configuration.
     *
     * The standard configuration consists of the following algorithms:
     * <ul>
     * <li> Hash: SHA256 </li>
     * <li> Symmetric Cipher: AES 128, AES 256 </li>
     * <li> Public Key Algorithm: DH2048, DH3027, MultiStream </li>
     * <li> SAS type: libase 32 </li>
     * <li> SRTP Authentication lengths: 32, 80 </li>
     *</ul>
     */
    void setStandardConfig();

    /**
     * Convenience function that sets the mandatory algorithms only.
     *
     * Mandatory algorithms are:
     * <ul>
     * <li> Hash: SHA256 </li>
     * <li> Symmetric Cipher: AES 128 </li>
     * <li> Public Key Algorithm: DH3027, MultiStream </li>
     * <li> SAS type: libase 32 </li>
     * <li> SRTP Authentication lengths: 32, 80 </li>
     *</ul>
     */
    void setMandatoryOnly();

    /**
     * Clear all configuration data.
     *
     * The functions clears all configuration data.
     */
    void clear();

    /**
     * Add an algorithm to configuration data.
     *
     * Adds the specified algorithm to the configuration data.
     * If no free configuration data slot is available the
     * function does not add the algorithm and returns -1. The
     * methods appends the algorithm to the existing algorithms.
     *
     * @param algoType
     *    Specifies which algorithm type to select
     * @param algo
     *    The enumeration of the algorithm to add.
     * @return
     *    Number of free configuration data slots or -1 on error
     */
    int32_t addAlgo(AlgoTypes algoType, AlgorithmEnum& algo);

    /**
     * Add an algorithm to configuration data at given index.
     *
     * Adds the specified algorithm to the configuration data vector
     * at a given index. If the index is larger than the actual size
     * of the configuration vector the method just appends the algorithm.
     *
     * @param algoType
     *    Specifies which algorithm type to select
     * @param algo
     *    The enumeration of the algorithm to add.
     * @param index
     *    The index where to add the algorihm
     * @return
     *    Number of free configuration data slots or -1 on error
     */
    int32_t addAlgoAt(AlgoTypes algoType, AlgorithmEnum& algo, int32_t index);

    /**
     * Remove a algorithm from configuration data.
     *
     * Removes the specified algorithm from configuration data. If
     * the algorithm was not configured previously the function does
     * not modify the configuration data and returns the number of
     * free configuration data slots.
     *
     * If an application removes all algorithms then ZRTP does not
     * include any algorithm into the hello message and falls back
     * to a predefined mandatory algorithm.
     *
     * @param algoType
     *    Specifies which algorithm type to select
     * @param algo
     *    The enumeration of the algorithm to remove.
     * @return
     *    Number of free configuration slots.
     */
    int32_t removeAlgo(AlgoTypes algoType, AlgorithmEnum& algo);

    /**
     * Returns the number of configured algorithms.
     *
     * @param algoType
     *    Specifies which algorithm type to select
     * @return
     *    The number of configured algorithms (used configuration
     *    data slots)
     */
    int32_t getNumConfiguredAlgos(AlgoTypes algoType);

    /**
     * Returns the identifier of the algorithm at index.
     *
     * @param algoType
     *    Specifies which algorithm type to select
     * @param index
     *    The index in the list of the algorihm type
     * @return
     *    A pointer the the algorithm enumeration. If the index
     *    does not point to a configured slot then the function
     *    returns NULL.
     *
     */
    AlgorithmEnum& getAlgoAt(AlgoTypes algoType, int32_t index);

    /**
     * Checks if the configuration data of the algorihm type already contains
     * a specific algorithms.
     *
     * @param algoType
     *    Specifies which algorithm type to select
     * @param algo
     *    The algorithm to check
     * @return
     *    True if the algorithm was found, false otherwise.
     *
     */
    bool containsAlgo(AlgoTypes algoType, AlgorithmEnum& algo);

    /**
     * Enables or disables trusted MitM processing.
     *
     * For further details of trusted MitM processing refer to ZRTP
     * specification, chapter 7.3
     *
     * @param yesNo
     *    If set to true then trusted MitM processing is enabled.
     */
    void setTrustedMitM(bool yesNo);

    /**
     * Check status of trusted MitM processing.
     *
     * @return
     *    Returns true if trusted MitM processing is enabled.
     */
    bool isTrustedMitM();

    /**
     * Enables or disables SAS signature processing.
     *
     * For further details of trusted MitM processing refer to ZRTP
     * specification, chapter 7.2
     *
     * @param yesNo
     *    If set to true then certificate processing is enabled.
     */
    void setSasSignature(bool yesNo);

    /**
     * Check status of SAS signature processing.
     *
     * @return
     *    Returns true if certificate processing is enabled.
     */
    bool isSasSignature();

    /**
     * Enables or disables paranoid mode.
     *
     * For further explanation of paranoid mode refer to the documentation
     * of ZRtp class.
     *
     * @param yesNo
     *    If set to true then paranoid mode is enabled.
     */
    void setParanoidMode(bool yesNo);

    /**
     * Check status of paranoid mode.
     *
     * @return
     *    Returns true if paranoid mode is enabled.
     */
    bool isParanoidMode();

    /// Helper function to print some internal data
    void printConfiguredAlgos(AlgoTypes algoTyp);

    Policy getSelectionPolicy()         {return selectionPolicy;}
    void setSelectionPolicy(Policy pol) {selectionPolicy = pol;}

  private:
    std::vector<AlgorithmEnum* > hashes;
    std::vector<AlgorithmEnum* > symCiphers;
    std::vector<AlgorithmEnum* > publicKeyAlgos;
    std::vector<AlgorithmEnum* > sasTypes;
    std::vector<AlgorithmEnum* > authLengths;

    bool enableTrustedMitM;
    bool enableSasSignature;
    bool enableParanoidMode;


    AlgorithmEnum& getAlgoAt(std::vector<AlgorithmEnum* >& a, int32_t index);
    int32_t addAlgo(std::vector<AlgorithmEnum* >& a, AlgorithmEnum& algo);
    int32_t addAlgoAt(std::vector<AlgorithmEnum* >& a, AlgorithmEnum& algo, int32_t index);
    int32_t removeAlgo(std::vector<AlgorithmEnum* >& a,  AlgorithmEnum& algo);
    int32_t getNumConfiguredAlgos(std::vector<AlgorithmEnum* >& a);
    bool containsAlgo(std::vector<AlgorithmEnum* >& a, AlgorithmEnum& algo);
    std::vector<AlgorithmEnum* >& getEnum(AlgoTypes algoType);

    void printConfiguredAlgos(std::vector<AlgorithmEnum* >& a);

    Policy selectionPolicy;

  protected:

  public:
};

/**
 * @}
 */
#endif

/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
