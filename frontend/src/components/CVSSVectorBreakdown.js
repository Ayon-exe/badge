import React, { useMemo } from 'react';
import { Info, BadgeCheck, BadgeAlert, BadgeX } from 'lucide-react';

const cvssMetrics = {
  AV: {
    L: {
      description: 'Attack Vector: Local',
      info: 'This means that the attacker must have direct access to the system in order to exploit the vulnerability.',
      color: 'bg-[#855e11] text-[#FDB52A] border-[#855e11]', // Brown (#855e11) and Amber (#FDB52A)
      icon: <BadgeAlert className="mr-2 text-lg text-[#FDB52A]" />,
    },
    A: {
      description: 'Attack Vector: Adjacent Network',
      info: 'This means that the attacker must be on the same network as the system in order to exploit the vulnerability.',
      color: 'bg-[#530006] text-[#FF5A65] border-[#530006]', // Dark Red (#530006) and Bright Pink (#FF5A65)
      icon: <BadgeX className="mr-2 text-lg text-[#FF5A65]" />,
    },
    N: {
      description: 'Attack Vector: Network',
      info: 'This means that the attacker can exploit the vulnerability from anywhere on the internet.',
      color: 'bg-[#530006] text-[#FF5A65] border-[#530006]', // Dark Red (#530006) and Bright Pink (#FF5A65)
      icon: <BadgeX className="mr-2 text-lg text-[#FF5A65]" />,
    },
    P: {
      description: 'Attack Vector: Physical',
      info: 'This means that the attacker must have direct access to the system in order to exploit the vulnerability.',
      color: 'bg-[#004122] text-[#14CA74] border-[#004122]', // Dark Green (#004122) and Bright Green (#14CA74)
      icon: <BadgeCheck className="mr-2 text-lg text-[#14CA74]" />,
    },
  },
  AC: {
    L: {
      description: 'Attack Complexity: Low',
      info: 'This means that the attacker does not need any special skills or knowledge to exploit the vulnerability.',
      color: 'bg-[#530006] text-[#FF5A65] border-[#530006]', // Dark Red (#530006) and Bright Pink (#FF5A65)
      icon: <BadgeX className="mr-2 text-lg text-[#FF5A65]" />,
    },
    H: {
      description: 'Attack Complexity: High',
      info: 'This means that the attacker needs special skills or knowledge to exploit the vulnerability.',
      color: 'bg-[#004122] text-[#14CA74] border-[#004122]', // Dark Green (#004122) and Bright Green (#14CA74)
      icon: <BadgeCheck className="mr-2 text-lg text-[#14CA74]" />,
    },
  },
  PR: {
    N: {
      description: 'Privileges Required: None',
      info: 'This means that the attacker can exploit the vulnerability without needing any special permissions.',
      color: 'bg-[#530006] text-[#FF5A65] border-[#530006]', // Dark Red (#530006) and Bright Pink (#FF5A65)
      icon: <BadgeX className="mr-2 text-lg text-[#FF5A65]" />,
    },
    L: {
      description: 'Privileges Required: Low',
      info: 'This means that the attacker needs some special permissions, but not full administrative access.',
      color: 'bg-[#855e11] text-[#FDB52A] border-[#855e11]', // Brown (#855e11) and Amber (#FDB52A)
      icon: <BadgeAlert className="mr-2 text-lg text-[#FDB52A]" />,
    },
    H: {
      description: 'Privileges Required: High',
      info: 'This means that the attacker needs full administrative access to exploit the vulnerability.',
      color: 'bg-[#004122] text-[#14CA74] border-[#004122]', // Dark Green (#004122) and Bright Green (#14CA74)
      icon: <BadgeCheck className="mr-2 text-lg text-[#14CA74]" />,
    },
  },
  UI: {
    N: {
      description: 'User Interaction: None',
      info: 'This means that the attacker can exploit the vulnerability without needing any user input.',
      color: 'bg-[#530006] text-[#FF5A65] border-[#530006]', // Dark Red (#530006) and Bright Pink (#FF5A65)
      icon: <BadgeX className="mr-2 text-lg text-[#FF5A65]" />,
    },
    R: {
      description: 'User Interaction: Required',
      info: 'This means that the attacker needs the user to perform some action in order to exploit the vulnerability.',
      color: 'bg-[#004122] text-[#14CA74] border-[#004122]', // Dark Green (#004122) and Bright Green (#14CA74)
      icon: <BadgeCheck className="mr-2 text-lg text-[#14CA74]" />,
    },
  },
  S: {
    U: {
      description: 'Scope: Unchanged',
      info: 'This means that the attacker does not gain any additional access or privileges by exploiting the vulnerability.',
      color: 'bg-[#004122] text-[#14CA74] border-[#004122]', // Dark Green (#004122) and Bright Green (#14CA74)
      icon: <BadgeCheck className="mr-2 text-lg text-[#14CA74]" />,
    },
    C: {
      description: 'Scope: Changed',
      info: 'This means that the attacker gains additional access or privileges by exploiting the vulnerability.',
      color: 'bg-[#530006] text-[#FF5A65] border-[#530006]', // Dark Red (#530006) and Bright Pink (#FF5A65)
      icon: <BadgeX className="mr-2 text-lg text-[#FF5A65]" />,
    },
  },
  C: {
    N: {
      description: 'Confidentiality: None',
      info: 'This means that the attacker does not gain access to any sensitive information by exploiting the vulnerability.',
      color: 'bg-[#004122] text-[#14CA74] border-[#004122]', // Dark Green (#004122) and Bright Green (#14CA74)
      icon: <BadgeCheck className="mr-2 text-lg text-[#14CA74]" />,
    },
    L: {
      description: 'Confidentiality: Low',
      info: 'This means that the attacker gains access to some sensitive information, but the impact is limited.',
      color: 'bg-[#855e11] text-[#FDB52A] border-[#855e11]', // Brown (#855e11) and Amber (#FDB52A)
      icon: <BadgeAlert className="mr-2 text-lg text-[#FDB52A]" />,
    },
    H: {
      description: 'Confidentiality: High',
      info: 'This means that the attacker gains access to highly sensitive information, and the impact is significant.',
      color: 'bg-[#530006] text-[#FF5A65] border-[#530006]', // Dark Red (#530006) and Bright Pink (#FF5A65)
      icon: <BadgeX className="mr-2 text-lg text-[#FF5A65]" />,
    },
  },
  I: {
    N: {
      description: 'Integrity: None',
      info: 'This means that the attacker does not gain the ability to modify any data by exploiting the vulnerability.',
      color: 'bg-[#004122] text-[#14CA74] border-[#004122]', // Dark Green (#004122) and Bright Green (#14CA74)
      icon: <BadgeCheck className="mr-2 text-lg text-[#14CA74]" />,
    },
    L: {
      description: 'Integrity: Low',
      info: 'This means that the attacker gains the ability to modify some data, but the impact is limited.',
      color: 'bg-[#855e11] text-[#FDB52A] border-[#855e11]', // Brown (#855e11) and Amber (#FDB52A)
      icon: <BadgeAlert className="mr-2 text-lg text-[#FDB52A]" />,
    },
    H: {
      description: 'Integrity: High',
      info: 'This means that the attacker gains the ability to modify highly sensitive data, and the impact is significant.',
      color: 'bg-[#530006] text-[#FF5A65] border-[#530006]', // Dark Red (#530006) and Bright Pink (#FF5A65)
      icon: <BadgeX className="mr-2 text-lg text-[#FF5A65]" />,
    },
  },
  A: {
    N: {
      description: 'Availability: None',
      info: 'This means that the attacker does not gain the ability to disrupt the system by exploiting the vulnerability.',
      color: 'bg-[#004122] text-[#14CA74] border-[#004122]', // Dark Green (#004122) and Bright Green (#14CA74)
      icon: <BadgeCheck className="mr-2 text-lg text-[#14CA74]" />,
    },
    L: {
      description: 'Availability: Low',
      info: 'This means that the attacker gains the ability to disrupt the system, but the impact is limited.',
      color: 'bg-[#855e11] text-[#FDB52A] border-[#855e11]', // Brown (#855e11) and Amber (#FDB52A)
      icon: <BadgeAlert className="mr-2 text-lg text-[#FDB52A]" />,
    },
    H: {
      description: 'Availability: High',
      info: 'This means that the attacker gains the ability to significantly disrupt the system, and the impact is significant.',
      color: 'bg-[#530006] text-[#FF5A65] border-[#530006]', // Dark Red (#530006) and Bright Pink (#FF5A65)
      icon: <BadgeX className="mr-2 text-lg text-[#FF5A65]" />,
    },
  },
};

const decodeCvssVector = (vector) => {
  const decodedVector = {};
  const vectorParts = vector?.split('/') || [];

  vectorParts.forEach((part) => {
    const [metric, value] = part?.split(':') || [];
    if (metric && value && cvssMetrics[metric] && cvssMetrics[metric][value]) {
      decodedVector[metric] = cvssMetrics[metric][value];
    }
  });

  return decodedVector;
};

const CVSSVectorBreakdown = ({ cvssMetrics }) => {
  const decodedVector = useMemo(() => {
    if (!cvssMetrics || cvssMetrics.vectorString === "N/A") {
      return null;
    }
    return decodeCvssVector(cvssMetrics.vectorString);
  }, [cvssMetrics]);

  const vectorBreakdown = useMemo(() => {
    if (!decodedVector) {
      return null;
    }
    return Object.keys(decodedVector).map((metric) => {
      const value = decodedVector[metric]?.description?.split(":")[1]?.trim();
      const color = decodedVector[metric]?.color;
      const icon = decodedVector[metric]?.icon;

      const textColor = color?.replace('bg-', '').replace('border-', '').split(' ')[0].replace('[', '').replace(']', '');
      const finalGradient = `linear-gradient(-45deg, ${textColor}, rgba(0,0,0,0.5))`;

      return (
        <div
          key={metric}
          className={`p-2 rounded-lg shadow-lg border-4 ${color} relative overflow-visible`} // Add thick border with current color
          style={{
            backdropFilter: "blur(10px)",
            background: finalGradient,
            backgroundSize: "400% 400%",
            height: "auto",
            maxWidth: "auto",
            zIndex: 10,
          }}
        >
          {/* Title Bar: Title with Info Icon */}
          <div className={`flex items-center justify-between p-2 ${color} border-b-4`} style={{ borderColor: color, borderRadius: '8px 8px 0 0' }}>
            <h1 className={`text-sm font- text-white`} style={{ wordWrap: 'break-word' }}>
              {decodedVector[metric].description.split(":")[0]}
            </h1>
            <div className="relative group">
              <Info className={`text-lg text-white cursor-pointer`} />
              <div
                className="absolute left-0 top-full mt-2 w-80 p-3 text-white bg-black border border-gray-700 rounded-lg shadow-lg opacity-0 group-hover:opacity-100 transition-opacity z-9999"
                style={{
                  position: 'absolute',
                  top: '80%',
                  left: '50%',
                  transform: 'translateX(-100%)',
                  
                  zIndex: 999,  
                  width: '300px',  // Adjust width to prevent it from being too wide
                  marginTop: '5px',  // Adds space between tooltip and icon
                  maxHeight: '150px', // Prevent tooltip from overflowing
                  overflowY: 'auto',  // Allow scrolling if text overflows
                }}
              >
                {decodedVector[metric]?.info}
              </div>
            </div>
          </div>

          {/* Second row: Action (Value and Icon) */}
          <div className="flex items-center justify-center mt-2 space-x-0 p-2">
            {icon && <div className="flex items-center justify-center">{icon}</div>}
            <span className={`text-lg font-bold text-white`} style={{ wordWrap: 'break-word' }}>
              {value}
            </span>
          </div>
        </div>
      );
    });
  }, [decodedVector]);

  return (
    <div className="container mx-auto p-2 px-0 md:p-6 lg:p-8 xl:p-10">
      <h2 className="text-2xl font-bold mb-4">CVSS Vector Breakdown:</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-2"> {/* Three boxes per row */}
        {vectorBreakdown}
      </div>
    </div>
  );
};

export default CVSSVectorBreakdown;