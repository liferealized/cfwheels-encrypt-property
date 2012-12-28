<cfcomponent mixin="model" output="false">

  <cffunction name="init" access="public" output="false">
    <cfscript>
      this.version = "1.1.7,1.1.8"; 
    </cfscript>
    <cfreturn this />
  </cffunction>
  
  <cffunction name="encryptProperty" access="public" output="false" returntype="void">
    <cfargument name="property" type="string" required="false" default="" />
    <cfargument name="key" type="string" required="true" />
    <cfscript>
      var loc = {};

      // normalize our arguments
      if (!StructKeyExists(arguments, "properties"))
        arguments.properties = arguments.property;

      // make sure we have space to save our property info
      if (!structKeyExists(variables.wheels.class, "encryptproperties"))
        variables.wheels.class.encryptproperties = {};

      for (loc.property in listToArray(arguments.properties))
      {
        variables.wheels.class.encryptproperties[loc.property] = { key = arguments.key };
        
        variables.property(name="#loc.property#beforedecrypt", sql=loc.property);
      }

      beforeValidation(method="$encryptProperties");
      afterFind(method="$decryptAfterFind");
      afterInitialization(method="$decryptAfterInitialization");
    </cfscript>
    <cfreturn />
  </cffunction>

  <cffunction name="$decryptAfterFind" access="public" output="false" returntype="struct">
    <cfscript>
      var loc = { properties = variables.wheels.class.encryptproperties};

      for (loc.property in loc.properties)
      {
        if (structKeyExists(arguments, loc.property))
        {
          if (!structKeyExists(arguments, loc.property & "beforedecrypt"))
            arguments[loc.property & "beforedecrypt"] = arguments[loc.property];

          if (compare(arguments[loc.property], arguments[loc.property & "beforedecrypt"]) neq 0)
            continue;

          if (len(arguments[loc.property]))
            arguments[loc.property] = $decrypt(value=arguments[loc.property], argumentCollection=loc.properties[loc.property]);
        }
      }
    </cfscript>
    <cfreturn arguments />
  </cffunction>

  <cffunction name="$decryptAfterInitialization" access="public" output="false" returntype="void">
    <cfargument name="properties" type="struct" required="false" default="#variables.wheels.class.encryptproperties#" />
    <cfscript>
      var loc = {};

      for (loc.property in arguments.properties)
      {
        if (structKeyExists(this, loc.property))
        {
          if (!structKeyExists(this, loc.property & "beforedecrypt"))
            this[loc.property & "beforedecrypt"] = this[loc.property];

          if (compare(this[loc.property], this[loc.property & "beforedecrypt"]) neq 0)
            continue;

          if (len(this[loc.property]))
            this[loc.property] = $decrypt(value=this[loc.property], argumentCollection=arguments.properties[loc.property]);
        }
      }
    </cfscript>
  </cffunction>

  <cffunction name="$encryptProperties" access="public" output="false" returntype="void">
    <cfargument name="properties" type="struct" required="false" default="#variables.wheels.class.encryptproperties#" />
    <cfscript>
      var loc = {};

      for (loc.property in arguments.properties)
        if (hasChanged(loc.property) and structKeyExists(this, loc.property))
          this[loc.property] = $encrypt(value=this[loc.property], argumentCollection=arguments.properties[loc.property]);
    </cfscript>
  </cffunction>

  <cffunction name="$encrypt" access="public" output="false" returntype="string">
    <cfargument name="value" type="string" required="true" />
    <cfargument name="key" type="string" required="true" />
    <cfreturn encrypt(arguments.value, arguments.key) />
  </cffunction>

  <cffunction name="$decrypt" access="public" output="false" returntype="string">
    <cfargument name="value" type="string" required="true" />
    <cfargument name="key" type="string" required="true" />
    <cfreturn decrypt(arguments.value, arguments.key) />
  </cffunction>
  
</cfcomponent>