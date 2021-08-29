/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at
 * docs/licenses/cddl.txt
 * or http://www.opensource.org/licenses/cddl1.php.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at
 * docs/licenses/cddl.txt.  If applicable,
 * add the following below this CDDL HEADER, with the fields enclosed
 * by brackets "[]" replaced with your own identifying information:
 *      Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 *
 *      Copyright 2010-2021 Ping Identity Corporation
 */
package com.pingidentity.directory.poc.plugins.groovy;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.regex.Pattern;

import com.unboundid.directory.sdk.common.types.Entry;
import com.unboundid.directory.sdk.common.types.InternalConnection;
import com.unboundid.directory.sdk.common.types.LogSeverity
import com.unboundid.directory.sdk.common.types.OperationContext;
import com.unboundid.directory.sdk.ds.config.VirtualAttributeProviderConfig;
import com.unboundid.directory.sdk.ds.scripting.ScriptedVirtualAttributeProvider;
import com.unboundid.directory.sdk.ds.types.DirectoryServerContext;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.StringArgument;



/**
 * This class provides a scripted virtual attribute provider
 * that will generate a virtual attribute whose value will be all 
 * values from the source-attribute in the children of the entry's parent
 * who are of the specified source-objectclass. It takes the following
 * configuration arguments:
 * <UL>
 *   <LI>source-attribute -- The name of the attribute in the pibling entries whose
 *       value will be mirrored.</LI>
 * </UL>
 * <UL>
 *    <LI>source-objectclass -- The objectclass of the parent/pibling entries.</LI>
 * </UL>
 */
public final class PiblingMirrorScriptedVirtualAttributeProvider
       extends ScriptedVirtualAttributeProvider
{
  /**
   * The name of the argument that will be used for the argument used to specify
   * the attribute whose values should be mirrored.
   */
  private static final String ARG_NAME_ATTR = "source-attribute";

  /**
   * The name of the argument whose value will be used to select the correct objectclass
   */
  private static final String ARG_NAME_OBJECTCLASS = "source-objectclass";   


  // The server context for the server in which this extension is running.
  private DirectoryServerContext serverContext;

  // The source attribute from which to obtain the data for the virtual
  // attribute.
  private volatile String sourceAttribute;
  
  // The target objectclass for the pibling entries
  private volatile String sourceObjectclass;



  /**
   * Creates a new instance of this virtual attribute provider.  All virtual
   * attribute provider implementations must include a default constructor, but
   * any initialization should generally be done in the
   * {@code initializeVirtualAttributeProvider} method.
   */
  public PiblingMirrorScriptedVirtualAttributeProvider()
  {
    // No implementation required.
  }



  /**
   * Updates the provided argument parser to define any configuration arguments
   * which may be used by this virtual attribute provider.  The argument parser
   * may also be updated to define relationships between arguments (e.g., to
   * specify required, exclusive, or dependent argument sets).
   *
   * @param  parser  The argument parser to be updated with the configuration
   *                 arguments which may be used by this virtual attribute
   *                 provider.
   *
   * @throws  ArgumentException  If a problem is encountered while updating the
   *                             provided argument parser.
   */
  @Override()
  public void defineConfigArguments(final ArgumentParser parser)
         throws ArgumentException
  {
    // Add an argument that allows you to specify the source attribute name.
    Character shortIdentifier = null;
    String    longIdentifier  = ARG_NAME_ATTR;
    boolean   required        = true;
    int       maxOccurrences  = 1;
    String    placeholder     = "{attr}";
    String    description     = "The name of the attribute whose values " +
         "should be mirrored to generate the values for the virtual attribute.";

    StringArgument arg = new StringArgument(shortIdentifier, longIdentifier,
         required, maxOccurrences, placeholder, description);
    arg.setValueRegex(Pattern.compile("^[a-zA-Z][a-zA-Z0-9\\\\-]*\$"),
                      "A valid attribute name is required.");
    parser.addArgument(arg);
	
	// Add an argument that allows you to specify the source objectclass.
    shortIdentifier = null;
    longIdentifier  = ARG_NAME_OBJECTCLASS;
    required        = true;
    maxOccurrences  = 1;
    placeholder     = "{attr}";
    description     = "The name of the objectclass that entries must have " +
         "to be mirrored for the values for the virtual attribute.";
		 
	arg = new StringArgument(shortIdentifier, longIdentifier,
         required, maxOccurrences, placeholder, description);
    arg.setValueRegex(Pattern.compile("^[a-zA-Z][a-zA-Z0-9\\\\-]*\$"),
                      "A valid objectclass name is required.");
    parser.addArgument(arg);
  }



  /**
   * Initializes this virtual attribute provider.
   *
   * @param  serverContext  A handle to the server context for the server in
   *                        which this extension is running.
   * @param  config         The general configuration for this virtual attribute
   *                        provider.
   * @param  parser         The argument parser which has been initialized from
   *                        the configuration for this virtual attribute
   *                        provider.
   *
   * @throws  LDAPException  If a problem occurs while initializing this virtual
   *                         attribute provider.
   */
  @Override()
  public void initializeVirtualAttributeProvider(
                   final DirectoryServerContext serverContext,
                   final VirtualAttributeProviderConfig config,
                   final ArgumentParser parser)
         throws LDAPException
  {
    this.serverContext = serverContext;

    // Get the source attribute name.
    StringArgument arg =
         (StringArgument) parser.getNamedArgument(ARG_NAME_ATTR);
    sourceAttribute = arg.getValue();
	
	// Get the source objectclass name.
    arg =
         (StringArgument) parser.getNamedArgument(ARG_NAME_OBJECTCLASS);
    sourceObjectclass = arg.getValue();
  }



  /**
   * Indicates whether the configuration contained in the provided argument
   * parser represents a valid configuration for this extension.
   *
   * @param  config               The general configuration for this virtual
   *                              attribute provider.
   * @param  parser               The argument parser which has been initialized
   *                              with the proposed configuration.
   * @param  unacceptableReasons  A list that can be updated with reasons that
   *                              the proposed configuration is not acceptable.
   *
   * @return  {@code true} if the proposed configuration is acceptable, or
   *          {@code false} if not.
   */
  @Override()
  public boolean isConfigurationAcceptable(
                      final VirtualAttributeProviderConfig config,
                      final ArgumentParser parser,
                      final List<String> unacceptableReasons)
  {
    // The argument parser will handle all of the necessary validation, so
    // we don't need to do anything here.
    return true;
  }



  /**
   * Attempts to apply the configuration contained in the provided argument
   * parser.
   *
   * @param  config                The general configuration for this virtual
   *                               attribute provider.
   * @param  parser                The argument parser which has been
   *                               initialized with the new configuration.
   * @param  adminActionsRequired  A list that can be updated with information
   *                               about any administrative actions that may be
   *                               required before one or more of the
   *                               configuration changes will be applied.
   * @param  messages              A list that can be updated with information
   *                               about the result of applying the new
   *                               configuration.
   *
   * @return  A result code that provides information about the result of
   *          attempting to apply the configuration change.
   */
  @Override()
  public ResultCode applyConfiguration(
                         final VirtualAttributeProviderConfig config,
                         final ArgumentParser parser,
                         final List<String> adminActionsRequired,
                         final List<String> messages)
  {
    // Get the new source attribute name.
    final StringArgument arg =
         (StringArgument) parser.getNamedArgument(ARG_NAME_ATTR);
    sourceAttribute = arg.getValue();

    return ResultCode.SUCCESS;
  }



  /**
   * Performs any cleanup which may be necessary when this virtual attribute
   * provider is to be taken out of service.
   */
  @Override()
  public void finalizeVirtualAttributeProvider()
  {
    // No implementation required.
  }



  /**
   * Indicates whether the server may cache values generated by this virtual
   * attribute provider for reuse against the same entry in the course of
   * processing the same operation.
   *
   * @return  {@code true} if the server may cache the value generated by this
   *          virtual attribute provider for reuse with the same entry in the
   *          same operation, or {@code false} if not.
   */
  @Override()
  public boolean mayCacheInOperation()
  {
    // The values of this virtual attribute are safe to cache.
    return true;
  }



  /**
   * Indicates whether this virtual attribute provider may generate attributes
   * with multiple values.
   *
   * @return  {@code true} if this virtual attribute provider may generate
   *          attributes with multiple values, or {@code false} if it will only
   *          generate single-valued attributes.
   */
  @Override()
  public boolean isMultiValued()
  {
    // If the source attribute is multi-valued, then the virtual attribute will
    // also be multi-valued.
    return true;
  }



  /**
   * Generates an attribute for inclusion in the provided entry.
   *
   * @param  operationContext  The operation context for the operation in
   *                           progress, if any.  It may be {@code null} if no
   *                           operation is available.
   * @param  entry             The entry for which the attribute is to be
   *                           generated.
   * @param  attributeName     The name of the attribute to be generated.
   *
   * @return  The generated attribute, or {@code null} if no attribute should be
   *          generated.
   */
  @Override()
  public Attribute generateAttribute(final OperationContext operationContext,
                                     final Entry entry,
                                     final String attributeName)
  {
    final String filter = "(objectclass=" + sourceObjectclass + ")";
	final String baseDN = entry.getParsedDN().getParentString();
	// may make this a ternary based on an arg
	final SearchScope scope = SearchScope.ONE; //SUBORDINATE_SUBTREE or ONE
	
	final LinkedHashSet<String>  values = new LinkedHashSet<String>();
	// search the sub of the parent for the specified objectclass
	try {
		InternalConnection conn = operationContext.getInternalUserConnection();
		SearchResult searchResult = conn.search(baseDN, scope, filter, sourceAttribute);
		
		if (searchResult.getEntryCount() < 1) {
			if (serverContext.debugEnabled()) {
				serverContext.debugInfo("Returning null because the search " +
				filter + " on base " + baseDN + "returned no results");
			}
			return null;
		}
			
		final List<SearchResultEntry> entries = searchResult.getSearchEntries();
		
		// get the attribute values of source-attribute from each search result
		for (final SearchResultEntry e : entries) {
			for (final Attribute attribute : e.getAttribute(sourceAttribute)) {
				for (final String string : attribute.getValues()) {
					values.add(string);
				}
			}
		}
	} catch (LDAPException le) {
		serverContext.logMessage(LogSeverity.MILD_ERROR, le.getExceptionMessage());
	}
	
	if (values.isEmpty()) {
		if (serverContext.debugEnabled()) {
			serverContext.debugInfo("Returning null because attribute " +
				sourceAttribute + " does not have any values in the entries returned by " +
				" the search " + filter + " on base " + baseDN);
		}
		return null;
	} else {
		final Attribute va = new Attribute(attributeName, values);
		if (serverContext.debugEnabled()) {
			serverContext.debugInfo("Generated virtual attribute " + va);
		}

		return va;
	}
  }
}
